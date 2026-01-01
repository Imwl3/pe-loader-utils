#include <windows.h>
#include <tlhelp32.h>
#include "ntstructs.h"
#include <intrin.h>

// Manual mapper - no LoadLibrary, no LdrLoadDll
// Maps DLL sections, fixes relocations, resolves imports, calls entry

typedef struct {
    PVOID ImageBase;        // 0
    PVOID NtHeaders;        // 8
    PVOID BaseReloc;        // 16
    PVOID ImportDir;        // 24
    PVOID EntryPoint;       // 32
    ULONGLONG FirstIATValue;// 40 (8-byte aligned)
    DWORD Status;           // 48
    DWORD DebugNameRVA;     // 52
    DWORD NumImports;       // 56
    DWORD LastError;        // 60
    char FailedModule[64];  // 64
} MANUAL_MAP_DATA;

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef DWORD (WINAPI *pGetLastError)(void);
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

// Shellcode that runs in target process
__attribute__((section(".map")))
void __stdcall Loader(MANUAL_MAP_DATA *pData) {
    if (!pData) return;

    pData->Status = 1;  // Started

    BYTE *pBase = (BYTE*)pData->ImageBase;
    IMAGE_NT_HEADERS64 *pNT = (IMAGE_NT_HEADERS64*)pData->NtHeaders;
    IMAGE_OPTIONAL_HEADER64 *pOpt = &pNT->OptionalHeader;

    pData->Status = 2;  // Parsed headers

    // Get kernel32 functions via PEB walk using RAW OFFSETS (Win10/11 x64)
    // PEB offsets: Ldr at 0x18
    // PEB_LDR_DATA offsets: InMemoryOrderModuleList at 0x20
    // LDR_DATA_TABLE_ENTRY offsets: InMemoryOrderLinks at 0x10, DllBase at 0x30, BaseDllName.Buffer at 0x60

    BYTE *pPEB = (BYTE*)__readgsqword(0x60);
    pData->Status = 3;  // Got PEB

    BYTE *pLdr = *(BYTE**)(pPEB + 0x18);  // PEB->Ldr
    LIST_ENTRY *pHead = (LIST_ENTRY*)(pLdr + 0x20);  // Ldr->InMemoryOrderModuleList
    LIST_ENTRY *pCurrent = pHead->Flink;
    HMODULE hKernel32 = NULL;

    pData->Status = 4;  // Walking module list

    // Find kernel32.dll
    while (pCurrent != pHead) {
        BYTE *pEntry = (BYTE*)pCurrent - 0x10;  // InMemoryOrderLinks is at offset 0x10
        WCHAR *name = *(WCHAR**)(pEntry + 0x60);  // BaseDllName.Buffer at 0x60
        if (name) {
            // Check for KERNEL32: 'k' 'e' ... '3' '2'
            if ((name[0] | 0x20) == 'k' &&
                (name[1] | 0x20) == 'e' &&
                name[6] == '3' &&
                name[7] == '2') {
                hKernel32 = *(HMODULE*)(pEntry + 0x30);  // DllBase at 0x30
                break;
            }
        }
        pCurrent = pCurrent->Flink;
    }

    if (!hKernel32) { pData->Status = 100; return; }  // Failed: no kernel32

    pData->Status = 5;  // Found kernel32

    // Get exports from kernel32
    BYTE *pK32 = (BYTE*)hKernel32;
    IMAGE_DOS_HEADER *pDosK = (IMAGE_DOS_HEADER*)pK32;
    IMAGE_NT_HEADERS64 *pNtK = (IMAGE_NT_HEADERS64*)(pK32 + pDosK->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *pExp = (IMAGE_EXPORT_DIRECTORY*)(pK32 +
        pNtK->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *pNames = (DWORD*)(pK32 + pExp->AddressOfNames);
    WORD *pOrds = (WORD*)(pK32 + pExp->AddressOfNameOrdinals);
    DWORD *pFuncs = (DWORD*)(pK32 + pExp->AddressOfFunctions);

    pLoadLibraryA fnLoadLibraryA = NULL;
    pGetProcAddress fnGetProcAddress = NULL;
    pGetLastError fnGetLastError = NULL;

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char *name = (char*)(pK32 + pNames[i]);
        DWORD funcRVA = pFuncs[pOrds[i]];

        // LoadLibraryA - check ends with 'yA' not 'yW' or 'xA'
        if (name[0] == 'L' && name[4] == 'L' && name[7] == 'r' &&
            name[10] == 'y' && name[11] == 'A' && name[12] == 0) {
            fnLoadLibraryA = (pLoadLibraryA)(pK32 + funcRVA);
        }
        // GetProcAddress - check ends with 'ss'
        if (name[0] == 'G' && name[3] == 'P' && name[7] == 'A' &&
            name[12] == 's' && name[13] == 's' && name[14] == 0) {
            fnGetProcAddress = (pGetProcAddress)(pK32 + funcRVA);
        }
        // GetLastError
        if (name[0] == 'G' && name[3] == 'L' && name[7] == 'E' &&
            name[10] == 'o' && name[11] == 'r' && name[12] == 0) {
            fnGetLastError = (pGetLastError)(pK32 + funcRVA);
        }
    }

    if (!fnLoadLibraryA || !fnGetProcAddress) { pData->Status = 101; return; }  // Failed: no exports

    pData->Status = 6;  // Found LoadLibraryA/GetProcAddress

    // Process relocations
    ULONGLONG delta = (ULONGLONG)(pBase - pOpt->ImageBase);
    if (delta && pData->BaseReloc) {
        pData->Status = 7;  // Processing relocations
        IMAGE_BASE_RELOCATION *pReloc = (IMAGE_BASE_RELOCATION*)pData->BaseReloc;
        while (pReloc->VirtualAddress) {
            WORD *pEntry = (WORD*)(pReloc + 1);
            DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (DWORD i = 0; i < count; i++) {
                if ((pEntry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG *pPatch = (ULONGLONG*)(pBase + pReloc->VirtualAddress + (pEntry[i] & 0xFFF));
                    *pPatch += delta;
                }
            }
            pReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pReloc + pReloc->SizeOfBlock);
        }
    }

    pData->Status = 8;  // Relocations done

    // Resolve imports
    if (pData->ImportDir) {
        pData->Status = 9;  // Processing imports
        IMAGE_IMPORT_DESCRIPTOR *pImport = (IMAGE_IMPORT_DESCRIPTOR*)pData->ImportDir;
        while (pImport->Name) {
            pData->DebugNameRVA = pImport->Name;  // Save for debugging
            char *modName = (char*)(pBase + pImport->Name);
            HMODULE hMod = fnLoadLibraryA(modName);

            if (!hMod) {
                // Capture error code
                if (fnGetLastError)
                    pData->LastError = fnGetLastError();
                // Copy failed module name for debugging
                for (int i = 0; i < 63 && modName[i]; i++)
                    pData->FailedModule[i] = modName[i];
                pData->FailedModule[63] = 0;
                pData->Status = 102;
                return;
            }

            ULONGLONG *pThunk = (ULONGLONG*)(pBase + pImport->OriginalFirstThunk);
            ULONGLONG *pIAT = (ULONGLONG*)(pBase + pImport->FirstThunk);

            while (*pThunk) {
                if (*pThunk & IMAGE_ORDINAL_FLAG64) {
                    *pIAT = (ULONGLONG)fnGetProcAddress(hMod, (LPCSTR)(*pThunk & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME *pName = (IMAGE_IMPORT_BY_NAME*)(pBase + *pThunk);
                    *pIAT = (ULONGLONG)fnGetProcAddress(hMod, pName->Name);
                }
                if (!*pIAT) { pData->Status = 103; return; }  // Failed: GetProcAddress

                // Debug: track first resolved address
                if (pData->NumImports == 0) {
                    pData->FirstIATValue = *pIAT;
                }
                pData->NumImports++;

                pThunk++;
                pIAT++;
            }
            pImport++;
        }
    }

    pData->Status = 10;  // Imports done

    // Call DllMain
    if (pData->EntryPoint) {
        pData->Status = 11;  // Calling DllMain
        DllMain_t pEntry = (DllMain_t)pData->EntryPoint;
        pEntry((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }

    pData->Status = 12;  // DllMain returned

    // Wipe PE headers
    for (DWORD i = 0; i < pOpt->SizeOfHeaders; i++)
        pBase[i] = 0;

    pData->Status = 99;  // SUCCESS!
}

void _start(void) {
    // Usage: injector.exe <PID> <DLL_PATH>

    LPWSTR cmdLine = GetCommandLineW();

    // Skip exe name (handle quotes)
    if (*cmdLine == '"') {
        cmdLine++;
        while (*cmdLine && *cmdLine != '"') cmdLine++;
        if (*cmdLine == '"') cmdLine++;
    } else {
        while (*cmdLine && *cmdLine != ' ') cmdLine++;
    }
    while (*cmdLine == ' ') cmdLine++;

    // Parse PID
    DWORD pid = 0;
    while (*cmdLine >= '0' && *cmdLine <= '9') {
        pid = pid * 10 + (*cmdLine - '0');
        cmdLine++;
    }
    while (*cmdLine == ' ') cmdLine++;

    // Strip quotes from path if present
    if (*cmdLine == '"') {
        cmdLine++;
        LPWSTR end = cmdLine;
        while (*end && *end != '"') end++;
        *end = 0;
    }

    if (!pid) {
        ExitProcess(1);
    }

    // Convert to full path if relative
    WCHAR fullPath[MAX_PATH];
    if (!GetFullPathNameW(cmdLine, MAX_PATH, fullPath, NULL)) {
        ExitProcess(2);
    }

    // Read DLL file
    HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) ExitProcess(2);

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *pFile = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, pFile, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Parse PE (use explicit 64-bit structures)
    IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)pFile;
    IMAGE_NT_HEADERS64 *pNT = (IMAGE_NT_HEADERS64*)(pFile + pDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER64 *pOpt = &pNT->OptionalHeader;
    IMAGE_SECTION_HEADER *pSec = IMAGE_FIRST_SECTION(pNT);

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) ExitProcess(3);

    // Allocate in target
    BYTE *pTarget = (BYTE*)VirtualAllocEx(hProc, NULL, pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTarget) ExitProcess(4);

    // Write headers
    WriteProcessMemory(hProc, pTarget, pFile, pOpt->SizeOfHeaders, NULL);

    // Write sections
    for (WORD i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData) {
            WriteProcessMemory(hProc, pTarget + pSec[i].VirtualAddress,
                pFile + pSec[i].PointerToRawData, pSec[i].SizeOfRawData, NULL);
        }
    }

    // Debug: dump raw PE header bytes
    char rawDbg[512];
    BYTE *optBase = (BYTE*)pOpt;
    wsprintfA(rawDbg,
        "RAW PE PARSE:\n"
        "pFile: 0x%p\n"
        "e_lfanew: 0x%lX\n"
        "pNT: 0x%p\n"
        "pOpt: 0x%p\n"
        "Magic: 0x%X (expect 0x20b)\n"
        "\n"
        "Bytes at pOpt+16 (EntryRVA):\n"
        "%02X %02X %02X %02X\n"
        "\n"
        "Bytes at pOpt+112+8 (ImportDir):\n"
        "%02X %02X %02X %02X (RVA)\n"
        "%02X %02X %02X %02X (Size)",
        pFile, pDos->e_lfanew, pNT, pOpt,
        pOpt->Magic,
        optBase[16], optBase[17], optBase[18], optBase[19],
        optBase[120], optBase[121], optBase[122], optBase[123],
        optBase[124], optBase[125], optBase[126], optBase[127]);
    MessageBoxA(NULL, rawDbg, "RAW PE DEBUG", MB_OK);

    // Setup loader data
    MANUAL_MAP_DATA mapData = {0};
    mapData.ImageBase = pTarget;
    mapData.NtHeaders = pTarget + pDos->e_lfanew;

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        mapData.BaseReloc = pTarget + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        mapData.ImportDir = pTarget + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // Always set entry point (don't check for 0, it's valid RVA)
    mapData.EntryPoint = pTarget + pOpt->AddressOfEntryPoint;

    char dbg2[256];
    wsprintfA(dbg2, "Entry calc:\npTarget: 0x%p\nRVA: 0x%lX\nResult: 0x%p",
              pTarget, pOpt->AddressOfEntryPoint, mapData.EntryPoint);
    MessageBoxA(NULL, dbg2, "Debug", MB_OK);

    // Write loader shellcode
    BYTE *pLoader = (BYTE*)VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pLoader, (PVOID)Loader, 0x800, NULL);

    // Write map data
    MANUAL_MAP_DATA *pRemoteData = (MANUAL_MAP_DATA*)(pLoader + 0x800);
    WriteProcessMemory(hProc, pRemoteData, &mapData, sizeof(mapData), NULL);

    char dbg[512];
    wsprintfA(dbg, "PE Info:\n\nAddressOfEntryPoint RVA: 0x%lX\nTarget base: 0x%p\nCalculated Entry: 0x%p\n\nImport RVA: 0x%lX\nImport Size: 0x%lX",
              pOpt->AddressOfEntryPoint, pTarget, mapData.EntryPoint,
              pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
              pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    MessageBoxA(NULL, dbg, "Manual Mapper", MB_OK);

    // Use CreateRemoteThread (simpler, more reliable)
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoader, pRemoteData, 0, NULL);
    if (!hThread) ExitProcess(5);

    MessageBoxA(NULL, "Thread created! Waiting...", "Manual Mapper", MB_OK);

    // Wait for loader to finish (short timeout to catch crashes)
    DWORD waitResult = WaitForSingleObject(hThread, 3000);

    // Check if process is still alive
    DWORD procExitCode = 0;
    GetExitCodeProcess(hProc, &procExitCode);

    // Read back status (might fail if process crashed)
    MANUAL_MAP_DATA result = {0};
    BOOL readOk = ReadProcessMemory(hProc, pRemoteData, &result, sizeof(result), NULL);

    if (procExitCode != STILL_ACTIVE) {
        char msg[256];
        wsprintfA(msg, "TARGET CRASHED!\n\nLast status before crash: %lu\nRead success: %d",
                  result.Status, readOk);
        MessageBoxA(NULL, msg, "Manual Mapper - CRASH", MB_OK | MB_ICONERROR);
        CloseHandle(hThread);
        CloseHandle(hProc);
        ExitProcess(50);
    }

    // Show status with MessageBox
    char msg[256];
    const char *statusMsg;
    switch (result.Status) {
        case 0:  statusMsg = "Never started"; break;
        case 1:  statusMsg = "Started"; break;
        case 2:  statusMsg = "Parsed headers"; break;
        case 3:  statusMsg = "Got PEB"; break;
        case 4:  statusMsg = "Walking modules"; break;
        case 5:  statusMsg = "Found kernel32"; break;
        case 6:  statusMsg = "Found exports"; break;
        case 7:  statusMsg = "Processing relocs"; break;
        case 8:  statusMsg = "Relocs done"; break;
        case 9:  statusMsg = "Processing imports"; break;
        case 10: statusMsg = "Imports done"; break;
        case 11: statusMsg = "Calling DllMain"; break;
        case 12: statusMsg = "DllMain returned"; break;
        case 99:
            wsprintfA(msg, "SUCCESS!\n\nImports resolved: %lu\nFirst IAT: 0x%llX\nEntry: 0x%p",
                      result.NumImports, result.FirstIATValue, result.EntryPoint);
            MessageBoxA(NULL, msg, "Manual Mapper - SUCCESS", MB_OK);
            CloseHandle(hThread);
            CloseHandle(hProc);
            ExitProcess(0);
        case 100: statusMsg = "FAIL: kernel32 not found"; break;
        case 101: statusMsg = "FAIL: exports not found"; break;
        case 102:
            wsprintfA(msg, "FAIL: LoadLibrary\nName RVA: 0x%lX\nModule: [%s]\nGetLastError: %lu",
                      result.DebugNameRVA, result.FailedModule, result.LastError);
            MessageBoxA(NULL, msg, "Manual Mapper - FAIL", MB_OK | MB_ICONERROR);
            CloseHandle(hThread);
            CloseHandle(hProc);
            ExitProcess(102);
        case 103: statusMsg = "FAIL: GetProcAddress"; break;
        default: statusMsg = "Unknown"; break;
    }
    wsprintfA(msg, "Loader Status: %lu\n%s", result.Status, statusMsg);
    MessageBoxA(NULL, msg, "Manual Mapper Debug", MB_OK);

    CloseHandle(hThread);
    CloseHandle(hProc);
    VirtualFree(pFile, 0, MEM_RELEASE);

    ExitProcess(result.Status == 99 ? 0 : 1);
}
