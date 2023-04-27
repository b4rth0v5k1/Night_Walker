

#include <windows.h>
//#include "utils.h"
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
	perunfart(pi.hProcess);

}
