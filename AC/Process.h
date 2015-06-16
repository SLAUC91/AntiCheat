#ifndef __Process_H__
#define __Process_H__

/*
Need to add padding to structs for x64 compilation
*/

#include <string>
#include <vector>
#include <Windows.h>
#include <winternl.h>
#include "ntrdf.h"

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

	struct Page_INFO
	{
		All_SYS::MEMORY_BASIC_INFORMATION memInfo;
		bool isDLLpage = false;
		std::wstring nativeFullNameMem;
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
	std::vector < Page_INFO > ReadProcessPageInfo(DWORD dwPID);

	std::vector < Handle_INFO > ListHandles(DWORD PID);
	std::vector < Thread_INFO > ListThreads(DWORD PID);
	std::vector < System_Module_INFO > ListSystemModules();

	std::vector < Module_INFO > Modules;
	std::vector < Handle_INFO > Handles;
	std::vector < Thread_INFO > Threads;
	std::vector < Page_INFO > Pages;

	BOOL ThreadInAddrModList(SYSTEM_EXTENDED_THREAD_INFORMATION & ThreadINFO);

	std::vector < DWORD > System_PID_List;
};

#endif