EXTERN wNtOpenProcess:DWORD              
EXTERN sysAddrNtOpenProcess:QWORD        


.CODE  ; Start the code section

; Procedure for the NtAllocateVirtualMemory syscall
sysNtOpenProcess PROC
    mov r10, rcx                                   
    mov eax, wNtOpenProcess               
    jmp QWORD PTR [sysAddrNtOpenProcess]  
sysNtOpenProcess ENDP                        

END