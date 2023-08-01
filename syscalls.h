//#pragma once
//
//#include <windows.h>
//#include "PEstructs.h"
//
//
//#ifdef __cplusplus   // If this header file is included in a C++ file, then this section will be true
//extern "C" {         // This is to ensure that the names of the functions are not mangled by the C++ compiler and are in C linkage format
//#endif
//NTSTATUS sysNtOpenProcess(
//	OUT PHANDLE ProcessHandle,
//	IN ACCESS_MASK DesiredAccess,
//	IN POBJECT_ATTRIBUTES ObjectAttributes,
//	IN PCLIENT_ID ClientId OPTIONAL);
//
//#ifdef __cplusplus  // End of the 'extern "C"' block if __cplusplus was defined
//}
//#endif