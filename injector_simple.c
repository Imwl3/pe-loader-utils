#include <windows.h>

// Simple LoadLibrary injector - just to test if injection works at all

void _start(void) {
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

    if (!pid) ExitProcess(1);

    // Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) ExitProcess(2);

    // Get DLL path length (wide string)
    DWORD pathLen = 0;
    LPWSTR p = cmdLine;
    while (*p) { pathLen++; p++; }
    pathLen = (pathLen + 1) * sizeof(WCHAR);

    // Allocate memory in target for DLL path
    LPVOID pRemotePath = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) ExitProcess(3);

    // Write DLL path to target
    WriteProcessMemory(hProc, pRemotePath, cmdLine, pathLen, NULL);

    // Get LoadLibraryW address (same in all processes due to ASLR)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    // Create remote thread to call LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemotePath, 0, NULL);
    if (!hThread) ExitProcess(4);

    // Wait for DLL to load
    WaitForSingleObject(hThread, 5000);

    // Cleanup
    VirtualFreeEx(hProc, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    ExitProcess(0);
}
