#ifndef __Process_H__
#define __Process_H__

/*
Need to add padding to structs for x64 compilation
*/

#include <string>
#include <vector>
#include <Windows.h>
#include <winternl.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define Max_DLLs 256
#define MAX_FILENAME 512

namespace All_SYS{
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0x0000,
		SystemProcessorInformation = 0x0001,
		SystemPerformanceInformation = 0x0002,
		SystemTimeOfDayInformation = 0x0003,
		SystemPathInformation = 0x0004,
		SystemProcessInformation = 0x0005,
		SystemCallCountInformation = 0x0006,
		SystemDeviceInformation = 0x0007,
		SystemProcessorPerformanceInformation = 0x0008,
		SystemFlagsInformation = 0x0009,
		SystemCallTimeInformation = 0x000A,
		SystemModuleInformation = 0x000B,
		SystemLocksInformation = 0x000C,
		SystemStackTraceInformation = 0x000D,
		SystemPagedPoolInformation = 0x000E,
		SystemNonPagedPoolInformation = 0x000F,
		SystemHandleInformation = 0x0010,
		SystemObjectInformation = 0x0011,
		SystemPageFileInformation = 0x0012,
		SystemVdmInstemulInformation = 0x0013,
		SystemVdmBopInformation = 0x0014,
		SystemFileCacheInformation = 0x0015,
		SystemPoolTagInformation = 0x0016,
		SystemInterruptInformation = 0x0017,
		SystemDpcBehaviorInformation = 0x0018,
		SystemFullMemoryInformation = 0x0019,
		SystemLoadGdiDriverInformation = 0x001A,
		SystemUnloadGdiDriverInformation = 0x001B,
		SystemTimeAdjustmentInformation = 0x001C,
		SystemSummaryMemoryInformation = 0x001D,
		SystemMirrorMemoryInformation = 0x001E,
		SystemPerformanceTraceInformation = 0x001F,
		SystemCrashDumpInformation = 0x0020,
		SystemExceptionInformation = 0x0021,
		SystemCrashDumpStateInformation = 0x0022,
		SystemKernelDebuggerInformation = 0x0023,
		SystemContextSwitchInformation = 0x0024,
		SystemRegistryQuotaInformation = 0x0025,
		SystemExtendServiceTableInformation = 0x0026,
		SystemPrioritySeperation = 0x0027,
		SystemVerifierAddDriverInformation = 0x0028,
		SystemVerifierRemoveDriverInformation = 0x0029,
		SystemProcessorIdleInformation = 0x002A,
		SystemLegacyDriverInformation = 0x002B,
		SystemCurrentTimeZoneInformation = 0x002C,
		SystemLookasideInformation = 0x002D,
		SystemTimeSlipNotification = 0x002E,
		SystemSessionCreate = 0x002F,
		SystemSessionDetach = 0x0030,
		SystemSessionInformation = 0x0031,
		SystemRangeStartInformation = 0x0032,
		SystemVerifierInformation = 0x0033,
		SystemVerifierThunkExtend = 0x0034,
		SystemSessionProcessInformation = 0x0035,
		SystemLoadGdiDriverInSystemSpace = 0x0036,
		SystemNumaProcessorMap = 0x0037,
		SystemPrefetcherInformation = 0x0038,
		SystemExtendedProcessInformation = 0x0039,
		SystemRecommendedSharedDataAlignment = 0x003A,
		SystemComPlusPackage = 0x003B,
		SystemNumaAvailableMemory = 0x003C,
		SystemProcessorPowerInformation = 0x003D,
		SystemEmulationBasicInformation = 0x003E,
		SystemEmulationProcessorInformation = 0x003F,
		SystemExtendedHandleInformation = 0x0040,
		SystemLostDelayedWriteInformation = 0x0041,
		SystemBigPoolInformation = 0x0042,
		SystemSessionPoolTagInformation = 0x0043,
		SystemSessionMappedViewInformation = 0x0044,
		SystemHotpatchInformation = 0x0045,
		SystemObjectSecurityMode = 0x0046,
		SystemWatchdogTimerHandler = 0x0047,
		SystemWatchdogTimerInformation = 0x0048,
		SystemLogicalProcessorInformation = 0x0049,
		SystemWow64SharedInformationObsolete = 0x004A,
		SystemRegisterFirmwareTableInformationHandler = 0x004B,
		SystemFirmwareTableInformation = 0x004C,
		SystemModuleInformationEx = 0x004D,
		SystemVerifierTriageInformation = 0x004E,
		SystemSuperfetchInformation = 0x004F,
		SystemMemoryListInformation = 0x0050,
		SystemFileCacheInformationEx = 0x0051,
		SystemThreadPriorityClientIdInformation = 0x0052,
		SystemProcessorIdleCycleTimeInformation = 0x0053,
		SystemVerifierCancellationInformation = 0x0054,
		SystemProcessorPowerInformationEx = 0x0055,
		SystemRefTraceInformation = 0x0056,
		SystemSpecialPoolInformation = 0x0057,
		SystemProcessIdInformation = 0x0058,
		SystemErrorPortInformation = 0x0059,
		SystemBootEnvironmentInformation = 0x005A,
		SystemHypervisorInformation = 0x005B,
		SystemVerifierInformationEx = 0x005C,
		SystemTimeZoneInformation = 0x005D,
		SystemImageFileExecutionOptionsInformation = 0x005E,
		SystemCoverageInformation = 0x005F,
		SystemPrefetchPatchInformation = 0x0060,
		SystemVerifierFaultsInformation = 0x0061,
		SystemSystemPartitionInformation = 0x0062,
		SystemSystemDiskInformation = 0x0063,
		SystemProcessorPerformanceDistribution = 0x0064,
		SystemNumaProximityNodeInformation = 0x0065,
		SystemDynamicTimeZoneInformation = 0x0066,
		SystemCodeIntegrityInformation = 0x0067,
		SystemProcessorMicrocodeUpdateInformation = 0x0068,
		SystemProcessorBrandString = 0x0069,
		SystemVirtualAddressInformation = 0x006A,
		SystemLogicalProcessorAndGroupInformation = 0x006B,
		SystemProcessorCycleTimeInformation = 0x006C,
		SystemStoreInformation = 0x006D,
		SystemRegistryAppendString = 0x006E,
		SystemAitSamplingValue = 0x006F,
		SystemVhdBootInformation = 0x0070,
		SystemCpuQuotaInformation = 0x0071,
		SystemNativeBasicInformation = 0x0072,
		SystemErrorPortTimeouts = 0x0073,
		SystemLowPriorityIoInformation = 0x0074,
		SystemBootEntropyInformation = 0x0075,
		SystemVerifierCountersInformation = 0x0076,
		SystemPagedPoolInformationEx = 0x0077,
		SystemSystemPtesInformationEx = 0x0078,
		SystemNodeDistanceInformation = 0x0079,
		SystemAcpiAuditInformation = 0x007A,
		SystemBasicPerformanceInformation = 0x007B,
		SystemQueryPerformanceCounterInformation = 0x007C,
		SystemSessionBigPoolInformation = 0x007D,
		SystemBootGraphicsInformation = 0x007E,
		SystemScrubPhysicalMemoryInformation = 0x007F,
		SystemBadPageInformation = 0x0080,
		SystemProcessorProfileControlArea = 0x0081,
		SystemCombinePhysicalMemoryInformation = 0x0082,
		SystemEntropyInterruptTimingInformation = 0x0083,
		SystemConsoleInformation = 0x0084,
		SystemPlatformBinaryInformation = 0x0085,
		SystemThrottleNotificationInformation = 0x0086,
		SystemHypervisorProcessorCountInformation = 0x0087,
		SystemDeviceDataInformation = 0x0088,
		SystemDeviceDataEnumerationInformation = 0x0089,
		SystemMemoryTopologyInformation = 0x008A,
		SystemMemoryChannelInformation = 0x008B,
		SystemBootLogoInformation = 0x008C,
		SystemProcessorPerformanceInformationEx = 0x008D,
		SystemSpare0 = 0x008E,
		SystemSecureBootPolicyInformation = 0x008F,
		SystemPageFileInformationEx = 0x0090,
		SystemSecureBootInformation = 0x0091,
		SystemEntropyInterruptTimingRawInformation = 0x0092,
		SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
		SystemFullProcessInformation = 0x0094,
		MaxSystemInfoClass = 0x0095
	} SYSTEM_INFORMATION_CLASS;

#ifdef _WIN64
	//redefine the struct in windows interal header to include undocumented values
	typedef struct _PEB_LDR_DATA {
		ULONG			Length;
		UCHAR			Initialized;
		ULONG64			SsHandle;
		LIST_ENTRY64	InLoadOrderModuleList;
		LIST_ENTRY64	InMemoryOrderModuleList;
		LIST_ENTRY64	InInitializationOrderModuleList;
		PVOID64			EntryInProgress;
		UCHAR			ShutdownInProgress;
		PVOID64			ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB{
		UCHAR				InheritedAddressSpace;
		UCHAR				ReadImageFileExecOptions;
		UCHAR				BeingDebugged;
		BYTE				Reserved0;
		ULONG				Reserved1;
		ULONG64				Reserved3;
		ULONG64				ImageBaseAddress;
		ULONG64				LoaderData;
		ULONG64				ProcessParameters;
	}PEB, *PPEB;

	/** A structure that holds information about a single module loaded by a process **/
	/** LIST_ENTRY is a link list pointing to the prev/next Module loaded **/
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY64		InLoadOrderModuleList;
		LIST_ENTRY64		InMemoryOrderModuleList;
		LIST_ENTRY64		InInitializationOrderModuleList;
		ULONG64				BaseAddress;
		ULONG64				EntryPoint;
		ULONG				SizeOfImage;	//bytes
		UNICODE_STRING		FullDllName;
		UNICODE_STRING		BaseDllName;
		ULONG				Flags;
		USHORT				LoadCount;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#else
	//redefine the struct in windows interal header to include undocumented values
	typedef struct _PEB_LDR_DATA {
		DWORD					Length;
		UCHAR					Initialized;
		PVOID	                SsHandle;
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY				InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		PVOID					EntryInProgress;
		UCHAR					ShutdownInProgress;
		PVOID					ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		BYTE Reserved2[9];
		PPEB_LDR_DATA LoaderData;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		BYTE Reserved3[448];
		ULONG SessionId;
	}PEB, *PPEB;

	/** A structure that holds information about a single module loaded by a process **/
	/** LIST_ENTRY is a link list pointing to the prev/next Module loaded **/
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY            InLoadOrderModuleList;
		LIST_ENTRY            InMemoryOrderModuleList;
		LIST_ENTRY            InInitializationOrderModuleList;
		PVOID                 BaseAddress;
		PVOID                 EntryPoint;
		ULONG                 SizeOfImage;
		UNICODE_STRING        FullDllName;
		UNICODE_STRING        BaseDllName;
		ULONG                 Flags;
		USHORT				  LoadCount;
		USHORT                 TlsIndex;
		LIST_ENTRY            HashTableEntry;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
		_ACTIVATION_CONTEXT *	EntryPointActivationContext;
		PVOID					PatchInformation;
		LIST_ENTRY				ForwarderLinks;
		LIST_ENTRY				ServiceTagLinks;
		LIST_ENTRY				StaticLinks;
		PVOID					ContextInformation;
		DWORD					OriginalBase;
		LARGE_INTEGER			LoadTime;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;
		DWORD  SizeOfImage;
		LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

	typedef struct _Module_DATA{
		char	fileName[MAX_FILENAME];
		MODULEINFO dllInfo;
	}MODULE_DATA, *PMODULE_DATA;

	typedef struct _MODULE_LIST{
		HANDLE	handle;
		HMODULE handleDLL[Max_DLLs];
		DWORD nDLLs;
		PMODULE_DATA moduleArray;
	}MODULE_LIST, *PMODULE_LIST;
}

typedef NTSTATUS(NTAPI *_ntQSI)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef struct _SYSTEM_MODULE {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _CLIENT_ID {
	HANDLE  UniqueProcess;
	HANDLE  UniqueThread;
} CLIENT_ID;

typedef struct _VM_COUNTERS {
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
} VM_COUNTERS;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;	//2 Run, 5 Wait
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* Vista and above */
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef NTSTATUS(NTAPI * _ZwReadVirtualMemory)
(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG NumberOfBytesToRead,
	OUT PULONG NumberOfBytesReaded
);

typedef NTSTATUS (NTAPI * pNtQueryInformationProcess)
(
	HANDLE, 
	PROCESSINFOCLASS, 
	PVOID, 
	ULONG, 
	PULONG
);

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;

	//Idealy we would use this to get the information of certain object
	//But it is located in kernal space so we would need a driver
	PVOID Object;

	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


class Process{
private:
	void FindModuleFromAddr(DWORD dwPID, std::wstring & wModule, DWORD dwThreadAddr, DWORD * pModStrAddr, int FullPathName);
	void BuildModuleArray(All_SYS::PMODULE_LIST pModList);
	void BuildModuleList(All_SYS::PMODULE_LIST pModList);
	All_SYS::PLDR_DATA_TABLE_ENTRY Process::GetNextNode(PCHAR nNode, int Offset);

public:

	Process(std::string Proc);
	~Process();

	struct Process_INFO{
		DWORD Process_ID = 0;
		std::string Process_Name = "";
		std::string Create_Time = "";
		ULONG HandleCount = 0;
		ULONG ModuleCount = 0;
		ULONG ThreadCount = 0;
	}Pinfo;

	struct Module_INFO : All_SYS::LDR_DATA_TABLE_ENTRY
	{
		std::wstring			FullDllName;
		std::wstring			BaseDllName;
	};

	struct Handle_INFO{
		ULONG PID;
		DWORD Handle;
		DWORD ObjectTypeNumber;
		std::string ObjectTypeName;
		std::string ObjectName;
	}HIF;

	struct Thread_INFO{
		//Thread Info Struct
		SYSTEM_EXTENDED_THREAD_INFORMATION ExtThreadInfo;
		std::string FullModPathToAddr = "";
		std::string BaseModPathToAddr = "";
	};

	struct System_Module_INFO{
		ULONG ModulesCount;
		std::vector<SYSTEM_MODULE> Modules;
	};

	Process_INFO GetProcessInfo(std::string & PN);

	std::vector < Module_INFO > ListModulesA(DWORD PID, int ListType, int Order);
	void ListModulesB(DWORD PID);

	std::vector < Handle_INFO > ListHandles(DWORD PID);
	std::vector < Thread_INFO > ListThreads(DWORD PID);
	std::vector < System_Module_INFO > ListSystemModules();

	std::vector < Module_INFO > Modules;
	std::vector < Handle_INFO > Handles;
	std::vector < Thread_INFO > Threads;

	BOOL ThreadInAddrModList(SYSTEM_EXTENDED_THREAD_INFORMATION & ThreadINFO);

	std::vector < DWORD > System_PID_List;
};

#endif