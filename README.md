# Night Walker

This is a shellcode runner I developpped to learn more about PerunsFart technique, but ended up adding more functionality.  
It enhanced my knowledge about windows API, malware development, debugging.   

You can find my detailed blog about this project and the results of my testing against AV/EDR here.
There will be probably a version 2 released with Indirect Syscall and dynamic syscall ID, but only in 2024 as I need to focus on other skills too.

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

## Mentions
People you need to follow who are doing an amazing job.
- [Processus](https://processus.site/) - Also assisted me and helped with the testing and development in this project.
- [dosxuz123](https://twitter.com/dosxuz123) - Helped me with some issues I had.
- [AliceCliment](https://twitter.com/AliceCliment) - Check her amazing latest blog [here](https://alice.climent-pommeret.red/posts/process-killer-driver/).
- [TheD1rkMtr](https://twitter.com/D1rkMtr) - He's constantly releasing really cool projects about malware dev.

## References
- https://institute.sektor7.net/
- https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
- https://dosxuz.gitlab.io/post/perunsfart/
- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
- https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/tree/main
- https://captmeelo.com/redteam/maldev/2021/11/22/picky-ppid-spoofing.html
- https://ph3n1x.com/posts/parse-ntdll-and-peb/
- https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/