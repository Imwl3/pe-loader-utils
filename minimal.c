// Minimal shellcode-style DLL - no CRT, no threads, no exceptions
#include <windows.h>

// Entry point - runs when DLL loads
BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Create a file as proof of injection (more reliable than MessageBox)
        HANDLE hFile = CreateFileA("C:\\injected.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char msg[] = "DLL loaded!\r\n";
            DWORD written;
            WriteFile(hFile, msg, sizeof(msg)-1, &written, NULL);
            CloseHandle(hFile);
        }
    }
    return TRUE;
}
