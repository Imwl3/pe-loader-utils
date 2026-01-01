// NO IMPORTS version - test if manual mapper works at all
typedef int BOOL;
typedef void* HINSTANCE;
typedef void* LPVOID;
typedef unsigned long DWORD;
#define TRUE 1
#define DLL_PROCESS_ATTACH 1

__declspec(dllexport) volatile int g_injected = 0;

BOOL __stdcall _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_injected = 0xDEADBEEF;  // Proof we ran
    }
    return TRUE;
}
