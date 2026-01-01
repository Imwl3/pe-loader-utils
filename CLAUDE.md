# Windows DLL Cross-Compilation (Linux)

## Build Command

```bash
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident -O2 -Wl,-e,_DllMainCRTStartup -o minimal.dll minimal.c -lkernel32
```

## Flags

| Flag | Purpose |
|------|---------|
| `-shared` | Build DLL instead of EXE |
| `-nostdlib` | No C runtime (shellcode-style) |
| `-fno-exceptions` | No exception handling |
| `-fno-asynchronous-unwind-tables` | No .eh_frame section |
| `-fno-ident` | No compiler version string |
| `-Wl,-e,_DllMainCRTStartup` | Set entry point |

## DLL Template

```c
#include <windows.h>

BOOL WINAPI _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // runs on load
    }
    return TRUE;
}
```

---

## EXE Build Command

```bash
x86_64-w64-mingw32-gcc -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident -O2 -Wl,-e,_start -o minimal.exe minimal.c -lkernel32
```

## EXE Template

```c
#include <windows.h>

void _start(void) {
    // Your code here
    ExitProcess(0);
}
```

---

## Manual Mapper Injector

**Files:**
- `ntstructs.h` - PEB/LDR structures (MinGW doesn't have them)
- `injector.c` - Manual mapper (no LoadLibrary)

**Build:**
```bash
x86_64-w64-mingw32-gcc -nostdlib -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident -O2 -Wl,-e,_start -o injector.exe injector.c -lkernel32
```

**Usage:**
```
injector.exe <PID> <path\to\dll.dll>
```

**What it does:**
1. Opens target process
2. Allocates RWX memory
3. Copies PE sections
4. Fixes relocations (delta from preferred base)
5. Resolves imports via PEB walk (no LoadLibrary in shellcode)
6. Calls DllMain(DLL_PROCESS_ATTACH)
7. Wipes PE headers
8. Thread hijack (no CreateRemoteThread)
