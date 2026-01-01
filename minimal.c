// Minimal shellcode-style DLL - no CRT, no threads, no exceptions
#include <windows.h>

// Entry point - runs when DLL loads
BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Intentionally crash to prove we got here
        *(volatile int*)0 = 0xDEAD;
    }
    return TRUE;
}
