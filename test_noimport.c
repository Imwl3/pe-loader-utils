// Test DLL with NO imports - just return TRUE
#include <windows.h>

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    // No MessageBox - no imports needed
    // Just write to a memory location as proof we ran
    if (fdwReason == DLL_PROCESS_ATTACH) {
        volatile int *p = (volatile int*)hinstDLL;
        p[0] = 0xDEADBEEF;  // Write magic value to prove we executed
    }
    return TRUE;
}
