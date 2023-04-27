# PerunsFart
I discoverd this technique on SEKTOR7 [blog](https://blog.sektor7.net/#!res/2021/perunsfart.md).

The idea is to grab a fresh copy of NTDLL from a suspended process and unhook our own process.

Defender goes blind.  
Defender for Endpoint triggered a scan at some point but then didn't detect anything. Probably because the payload get executed in another process.  

Techniques implemented:
- PEB parsing and dynamic resolution of NTDLL functions. I only used **CreateProcess** because NtCreateUserProcess is a pain in the ass to implement.
- NtTraceEvent patching
- NTDLL unhooking
- EarlyBird process injection

TODO:
- AMSI patching ?
- Module stomping