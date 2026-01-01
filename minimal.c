// Absolute minimum DLL - no imports at all
typedef int BOOL;
typedef void* HINSTANCE;
typedef void* LPVOID;
typedef unsigned long DWORD;
#define TRUE 1
#define DLL_PROCESS_ATTACH 1

BOOL __stdcall _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
