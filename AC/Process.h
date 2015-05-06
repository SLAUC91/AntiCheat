#ifndef __Process_H__
#define __Process_H__

#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <iostream>
#include <limits.h>

//Undocumented system information struct
#define SystemExtendedProcessInformation 57
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(WINAPI *_ntQSI)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
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
	ULONG ThreadState;
	ULONG WaitReason;
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

/** A structure that holds information about a single module loaded by a process **/
/** LIST_ENTRY is a link list pointing to the prev/next Module loaded **/
typedef struct _LDR_MODULE
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
	SHORT                 LoadCount;
	SHORT                 TlsIndex;
	LIST_ENTRY            HashTableEntry;
	ULONG                 TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

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

	//redefine the struct in windows interal header to include undocumented values
	typedef struct _PEB_LDR_DATA {
		ULONG                   Length;
		BOOLEAN                 Initialized;
		PVOID                   SsHandle;
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	//Read Memory Template
	template <class T>
	T Read_Mem(HANDLE P, DWORD dwAddress)
	{
		T vRead;
		_ZwReadVirtualMemory ZwReadVirtualMemory = (_ZwReadVirtualMemory)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtReadVirtualMemory");
		ZwReadVirtualMemory(P, (LPVOID)dwAddress, &vRead, sizeof(T), NULL);
		return vRead;
	}

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

	struct Module_INFO{
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		std::wstring			FullDllName;
		std::wstring			BaseDllName;
		SHORT                   LoadCount;
		ULONG                   TimeDateStamp;
		bool					Dll_Flagged;
	};

	struct Handle_INFO{
		ULONG PID;
		DWORD Handle;
		DWORD ObjectTypeNumber;
		std::string ObjectTypeName;
		std::string ObjectName;
	}HIF;

	Process_INFO GetProcessInfo(std::string & PN);

	std::vector < Module_INFO > ListModules(DWORD PID);
	std::vector < Handle_INFO > ListHandles(DWORD PID);

	std::vector < Module_INFO > Modules;
	std::vector < Handle_INFO > Handles;

	std::vector < DWORD > System_PID_List;
};

#endif