# AntiCheat
Scanning Suite - Windows

##Purpose
The purpose of this software is to scan for certain malicious activity that occur in the gaming median. The current development uses Native Documented and Undocumented WinAPI functions to analysis the execution of all process under certain constraints.

##Features
1. USN Scanning 
2. DNS Scanning
3. Modules Scanning (PEB Lists, QueryVirtualMemory)
4. Handle Scanning (All events, Files, Process Handles)
5. Thread Scannning
6. Driver & System Module Scannning
7. Pattern Scanner*
8. PE & PEB Parsing
9. User-Mode Hook Detection (IAT)
10. MSR Hook Detection
11. IDT Hook Detection
12. SSDT Hook Detection
13. IRP Handlers Hook Detection
14. x32 Driver*
 
##In Development
1. x64 Driver
2. Heuristic Based Detection
3. Debugging Counter-Countermeasures
4. Code Tracing
5. Screen Capture
6. General Driver and Engine Integration*
 
*Note: Not fully Integrated

##Limitations
The biggest limitation currently is the absence of a driver as it is a real pain to develop a x64 bit driver and get it signed, I will probably develop a driver under test mode. Unless I decide to release the driver bundled with a signed vulnerable Third-Party driver allowing me to bypass KMCS. As for bypassing KPP (PatchGuard) it is relatively straightforward to disable these checks with a KMD and hook the SSDT, but a large investment of time is required. So all in all soon. 

Another underlying problem is that anyone can hook the underlying functions used by the driver. Of particular concern ZwQuerySystemInformation, so I will also be implementing the raw assembly version of certain functions. Also portability problems for WIN 8 & 10 will be addressed in the near future.  
