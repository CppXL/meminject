#include <Windows.h>
#include <winnt.h>
#include <iostream>

BOOL MapSection(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS64 pNTHeader, LPVOID ImageBase);
BOOL DoReloctionTable(LPVOID lpBaseAddress);
BOOL DoImportTable(LPVOID lpBaseAddress);
BOOL SetImageBaseAddr(LPVOID ImageBase);
BOOL CallDllMain(LPVOID ImageBase);
FARPROC GetFuncAddrByName(LPVOID DllImageBase, char *funcname);
typedef BOOL(APIENTRY *_DllMain)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
typedef INT(FAR WINAPI *_add)(int x, int y);
typedef WINUSERAPI int(WINAPI *MessageBoxFunc)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);