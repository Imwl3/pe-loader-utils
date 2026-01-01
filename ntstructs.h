// NT structures for 64-bit Windows 10/11 manual mapping
#pragma once
#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// PEB_LDR_DATA for x64
typedef struct _PEB_LDR_DATA {
    ULONG Length;                           // 0x00
    UCHAR Initialized;                      // 0x04
    PVOID SsHandle;                         // 0x08
    LIST_ENTRY InLoadOrderModuleList;       // 0x10
    LIST_ENTRY InMemoryOrderModuleList;     // 0x20
    LIST_ENTRY InInitializationOrderModuleList; // 0x30
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// LDR_DATA_TABLE_ENTRY for x64 - using offsets directly
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;            // 0x00
    LIST_ENTRY InMemoryOrderLinks;          // 0x10
    LIST_ENTRY InInitializationOrderLinks;  // 0x20
    PVOID DllBase;                          // 0x30
    PVOID EntryPoint;                       // 0x38
    ULONG SizeOfImage;                      // 0x40
    ULONG Pad;                              // 0x44 (alignment)
    UNICODE_STRING FullDllName;             // 0x48
    UNICODE_STRING BaseDllName;             // 0x58
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// PEB for x64 - minimal, just what we need
typedef struct _PEB {
    UCHAR InheritedAddressSpace;            // 0x00
    UCHAR ReadImageFileExecOptions;         // 0x01
    UCHAR BeingDebugged;                    // 0x02
    UCHAR BitField;                         // 0x03
    UCHAR Padding[4];                       // 0x04
    PVOID Mutant;                           // 0x08
    PVOID ImageBaseAddress;                 // 0x10
    PEB_LDR_DATA *Ldr;                      // 0x18
} PEB, *PPEB;
