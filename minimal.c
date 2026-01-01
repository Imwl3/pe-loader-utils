#include <windows.h>

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Simple test - create file in temp
        char path[MAX_PATH];
        GetTempPathA(MAX_PATH, path);
        lstrcatA(path, "INJECTED.txt");
        HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            char msg[] = "Manual mapped!\r\n";
            DWORD written;
            WriteFile(hFile, msg, sizeof(msg)-1, &written, NULL);
            CloseHandle(hFile);
        }
    }
    return TRUE;
}
