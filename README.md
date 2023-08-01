# Night Walker

This is a shellcode runner I developpped to learn more about PerunsFart technique, but ended up adding more functionality.  
It enhanced my knowledge about windows API, malware development, debugging.   

You can find my detailed blog about this project here.
There will be probably a version 2 released with Indirect Syscall and dynamic syscall ID, but only in 2024 as I will want to use it on my job first.

Also for real engagements, it's better to apply the techniques described here with a DLL  Hijacking by proxying instead of a standaolne executable.

For my french friends, you can check Processus [blog](https://processus.site/contournement-antivirus-edr.html) about AV/EDR bypass, he has a good explanation in french of most of the techniques described here and also assisted me during the development of this project.
## Techniques implemented:
- PEB parsing and dynamic resolution of NTDLL functions. I only used **CreateProcess** because NtCreateUserProcess is a pain in the ass to implement.
- NtTraceEvent patching
- AMSI Patching
- NTDLL unhooking
- EarlyBird process injection
- Heap encryption
- IAT hooking

