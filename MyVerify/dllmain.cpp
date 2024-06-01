// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include <stdio.h>

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
	PCHAR ThunkName;
	PVOID ThunkOldAddress;
	PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
	PWCHAR DllName;
	ULONG DllFlags;
	PVOID DllAddress;
	PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef void (NTAPI* RTL_VERIFIER_DLL_LOAD_CALLBACK) (
	PWSTR DllName,
	PVOID DllBase,
	SIZE_T DllSize,
	PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_DLL_UNLOAD_CALLBACK) (
	PWSTR DllName,
	PVOID DllBase,
	SIZE_T DllSize,
	PVOID Reserved);
typedef void (NTAPI* RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK) (
	PVOID AllocationBase,
	SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
	ULONG Length;
	PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
	RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
	RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;

	PWSTR VerifierImage;
	ULONG VerifierFlags;
	ULONG VerifierDebug;

	PVOID RtlpGetStackTraceAddress;
	PVOID RtlpDebugPageHeapCreate;
	PVOID RtlpDebugPageHeapDestroy;

	RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR;

#define DLL_PROCESS_VERIFIER 4

BOOL WINAPI HookGetMessage(PMSG msg, HWND hWnd, UINT filterMin, UINT filterMax);
HANDLE WINAPI HookCreateFile(PCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD flags, HANDLE hTemplate);

RTL_VERIFIER_THUNK_DESCRIPTOR user32Hooks[] = {
	{ (PCHAR)"GetMessageW", nullptr, HookGetMessage },
	{ nullptr, nullptr, nullptr },
};

RTL_VERIFIER_THUNK_DESCRIPTOR kernelbaseHooks[] = {
	{ (PCHAR)"CreateFileW", nullptr, HookCreateFile },
	{ nullptr, nullptr, nullptr },
};

RTL_VERIFIER_DLL_DESCRIPTOR dlls[] = {
	{ (PWCHAR)L"user32.dll", 0, nullptr, user32Hooks },
	{ (PWCHAR)L"kernelbase.dll", 0, nullptr, kernelbaseHooks },
	{ nullptr, 0, nullptr, nullptr },
};

RTL_VERIFIER_PROVIDER_DESCRIPTOR desc = {
	sizeof(desc),
	dlls,
	[](auto, auto, auto, auto) {},
	[](auto, auto, auto, auto) {},
	nullptr, 0, 0,
	nullptr, nullptr, nullptr,
	[](auto, auto) {},
};


BOOL WINAPI DllMain(HMODULE hModule, DWORD reason, PVOID lpReserved) {
	switch (reason) {
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;

		case DLL_PROCESS_VERIFIER:
			*(PVOID*)lpReserved = &desc;
			break;
	}
	return TRUE;
}

BOOL WINAPI HookGetMessage(PMSG msg, HWND hWnd, UINT filterMin, UINT filterMax) {
	// get original function
	static const auto orgGetMessage = (decltype(::GetMessageW)*)user32Hooks[0].ThunkOldAddress;
	auto result = orgGetMessage(msg, hWnd, filterMin, filterMax);
	char text[128];
	sprintf_s(text, "Received message 0x%X for hWnd 0x%p\n", msg->message, msg->hwnd);
	OutputDebugStringA(text);
	return result;
}

HANDLE WINAPI HookCreateFile(PCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD flags, HANDLE hTemplate) {
	// get original function
	static const auto orgCreateFile = (decltype(::CreateFileW)*)kernelbaseHooks[0].ThunkOldAddress;
	auto hFile = orgCreateFile(path, access, share, sa, cd, flags, hTemplate);
	char text[512];
	if (hFile == INVALID_HANDLE_VALUE)
		sprintf_s(text, "Failed to open file %ws (%u)\n", path, ::GetLastError());
	else
		sprintf_s(text, "Opened file %ws successfuly (0x%p)\n", path, hFile);

	OutputDebugStringA(text);
	return hFile;
}

