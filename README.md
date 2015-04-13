# AntiCheat
Scanning Suite - Windows

##Purpose
The purpose of this software is to scan for certain malicious activity that occur in the gaming median. The current development uses Native Documented and Undocumented WinAPI functions to analysis the execution of all process under certain constraints.

##Features
1. USN Scanning 
2. DNS Scanning (Soon)
3. Modules Scanning 
4. Handle Scanning (All events, Files, Process Handles)
5. PEB Parsing (Soon)
6. CPU and Memory Usage 
7. Screen Capture (Soon)
8. Reverse Engineering Countermeasures (Soon)
9. Driver (Soon - Current development is primary focused on User Mode)
10. Heuristic Based Detection
11. Debugging Counter-Countermeasures (Soon)
12. Kernel-Mode Hook Detection (Soon)
13. IA32_SYSENTER_EIP Detection (Soon)
14. INT 0x2E Detection (Soon)
15. SSDT Detection (Soon)
16. IRP Handlers Detection (Soon)
17. User-Mode Hook Detection (Soon)
18. Code Tracing

##Limitations
The biggest limitation currently is the absence of a driver as it is a real pain to develop a x64 bit driver and get it signed, I will probably develop a driver under test mode. Unless I decide to release the driver bundled with a signed vulnerable Third-Party driver allowing me to bypass KMCS. As for bypassing KPP (PatchGuard) it is relatively straightforward to disable these checks with a KMD and hook the SSDT, but a large investment of time is required. So all in all soon. 

##Intention
So you may ask why I have decided to develop this well the answer to that question is two fold. First in the development of this I have reverse engineered existing Anti-Cheat solutions thus allowing me to write bypasses to them. Second it has given me a the fundamentals to rootkit development and detection.  
