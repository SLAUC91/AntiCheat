# AntiCheat
Scanning Suite - Windows

##Purpose
The purpose of this software is to scan for certain malicious activity that occur in the gaming median. The current development uses Native Documented and Undocumented WinAPI functions to analysis the execution of all process under certain constraints.

##Features
1. USN Scanning 
2. DNS Scanning
3. Modules Scanning 
4. Handle Scanning (All events, Files, Process Handles)
5. PE & PEB Parsing
6. User-Mode Hook Detection (IAT)
 
##In Development
1. Driver (Soon - Current development is primary focused on User Mode)
2. Heuristic Based Detection
3. Debugging Counter-Countermeasures
4. Kernel-Mode Hook Detection
5. IA32_SYSENTER_EIP Detection
6. INT 0x2E Detection
7. SSDT Detection
8. IRP Handlers Detection
9. Code Tracing
10. Screen Capture

##Limitations
The biggest limitation currently is the absence of a driver as it is a real pain to develop a x64 bit driver and get it signed, I will probably develop a driver under test mode. Unless I decide to release the driver bundled with a signed vulnerable Third-Party driver allowing me to bypass KMCS. As for bypassing KPP (PatchGuard) it is relatively straightforward to disable these checks with a KMD and hook the SSDT, but a large investment of time is required. So all in all soon. 
