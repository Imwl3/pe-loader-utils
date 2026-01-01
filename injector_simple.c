#include <windows.h>

// Simple LoadLibrary injector with MessageBox debugging

void ShowError(const char *step, DWORD err) {
    char buf[256];
    wsprintfA(buf, "%s\nError: %lu", step, err);
    MessageBoxA(NULL, buf, "Injector Debug", MB_OK);
}

void ShowSuccess(const char *msg) {
    MessageBoxA(NULL, msg, "Injector Debug", MB_OK);
}

void _start(void) {
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

    // Strip quotes from DLL path if present
    if (*cmdLine == '"') {
        cmdLine++;
        LPWSTR end = cmdLine;
        while (*end && *end != '"') end++;
        *end = 0;
    }

    if (!pid) {
        ShowError("No PID provided", 0);
        ExitProcess(1);
    }

    if (!*cmdLine) {
        ShowError("No DLL path provided", 0);
        ExitProcess(10);
    }

    // Convert to full path if relative
    WCHAR fullPath[MAX_PATH];
    if (!GetFullPathNameW(cmdLine, MAX_PATH, fullPath, NULL)) {
        ShowError("GetFullPathNameW failed", GetLastError());
        ExitProcess(16);
    }
    cmdLine = fullPath;

    // Show parsed values
    char dbg[512];
    wsprintfA(dbg, "PID: %lu\nPath: %S", pid, cmdLine);
    ShowSuccess(dbg);

    // Check if DLL exists locally first
    DWORD attrs = GetFileAttributesW(cmdLine);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        ShowError("DLL file not found", GetLastError());
        ExitProcess(11);
    }

    ShowSuccess("DLL file exists");

    // Try loading DLL locally first as a test
    HMODULE hTest = LoadLibraryW(cmdLine);
    if (!hTest) {
        wsprintfA(dbg, "LOCAL LoadLibrary failed!\nError: %lu", GetLastError());
        ShowError(dbg, GetLastError());
        ExitProcess(15);
    }
    FreeLibrary(hTest);
    ShowSuccess("LOCAL LoadLibrary OK - DLL is valid");

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        ShowError("OpenProcess failed", GetLastError());
        ExitProcess(2);
    }

    ShowSuccess("OpenProcess OK");

    // Get DLL path length (wide string)
    DWORD pathLen = 0;
    LPWSTR p = cmdLine;
    while (*p) { pathLen++; p++; }
    pathLen = (pathLen + 1) * sizeof(WCHAR);

    // Allocate memory in target for DLL path
    LPVOID pRemotePath = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        ShowError("VirtualAllocEx failed", GetLastError());
        ExitProcess(3);
    }

    wsprintfA(dbg, "VirtualAllocEx OK\nRemote addr: 0x%p", pRemotePath);
    ShowSuccess(dbg);

    // Write DLL path to target
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pRemotePath, cmdLine, pathLen, &written)) {
        ShowError("WriteProcessMemory failed", GetLastError());
        ExitProcess(12);
    }

    wsprintfA(dbg, "WriteProcessMemory OK\nBytes: %llu", (unsigned long long)written);
    ShowSuccess(dbg);

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    wsprintfA(dbg, "LoadLibraryW addr: 0x%p", pLoadLibraryW);
    ShowSuccess(dbg);

    // Create remote thread to call LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemotePath, 0, NULL);
    if (!hThread) {
        ShowError("CreateRemoteThread failed", GetLastError());
        ExitProcess(4);
    }

    ShowSuccess("CreateRemoteThread OK - waiting...");

    // Wait for DLL to load and get result
    WaitForSingleObject(hThread, 10000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    wsprintfA(dbg, "Thread finished\nLoadLibrary returned: 0x%lX", exitCode);
    ShowSuccess(dbg);

    // Cleanup
    VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    if (exitCode == 0) {
        ShowError("LoadLibrary returned NULL!", 0);
        ExitProcess(20);
    }

    ShowSuccess("Injection successful!");
    ExitProcess(0);
}
