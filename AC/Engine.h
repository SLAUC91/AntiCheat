#ifndef __ENG_H__
#define __ENG_H__

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "Process.h"

typedef struct _DNS_CACHE_ENTRY {
	struct _DNS_CACHE_ENTRY* pNext; 
	PWSTR pszName; 
	unsigned short wType; 
	unsigned short wDataLength; 
	unsigned long dwFlags; 
} DNSCACHEENTRY, *PDNSCACHEENTRY;

typedef int(WINAPI *DNS_GET_CACHE_DATA_TABLE)(PDNSCACHEENTRY);

class Engine{
private:
	void show_record(USN_RECORD * record);
	bool check_record(USN_RECORD * record, std::wstring s_filename);

	struct USN{
		std::wstring Filename;
		LARGE_INTEGER Timestamp;
		DWORD Reason;
		DWORD SecurityId;
		DWORD FileAttributes;
	};

	//Conflict and Unknown module list
	std::vector<Process::Module_INFO> Send_MOD_List;

	std::vector<USN> USN_LIST;	//List of Flagged USN
	std::vector<_DNS_CACHE_ENTRY> DNS_LIST;	//List of Flagged DNS

	//Send Method change this to whatever your serial/deserialization method is
	template <class T>
	int Send_Object(T Object)
	{
		return 1;
	}

	//Our attach process name
	std::string ProcN;

	//Vector containing the process that open our process
	//Technically you don't need this vector and you could just
	//do your work inline
	std::vector < DWORD > PID_H;

public:
	float stat_counter = 0.0f;

	Engine(std::string Proc);
	~Engine();

	//Serverside Process Object - Proof of concept
	//We just create the list at startup but in production
	//Object will be streamed at startup
	Process * PreLoaderINFO;

	//WString to String
	std::string Engine::ws2s(const std::wstring & s);

	//String to WString
	std::wstring Engine::s2ws(const std::string & s);

	int GetPrcessorInfo();

	struct DLLcontainer{
		std::string Name;						//Name of DLL
		std::vector<std::string> ImpFuncVec;	//Functions in DLL
	}cDLL;

	struct PEFunctions{
		//Export Functions
		std::vector<std::string> ExpFuncVec;
		//Import Functiosn & DLLs
		std::vector<DLLcontainer> ImpDllVec;
	}Functions;

	struct PeInfo{
		PEFunctions * Func = nullptr;
		std::string Name = " ";
	};


	void CompareModules(std::vector<Process::Module_INFO> &A, std::vector<Process::Module_INFO> &B);

	USN_RECORD * GetUSN(std::wstring & CheckFor);
	DNSCACHEENTRY * GetDNS(std::wstring & s_filename);

	void Check_Handles(Process * Proc);
	void Check_Threads(Process * Proc);

	//Fill the Import and Export Vectors
	void GetPeInfo(std::string FilePath);

	void DLL_Cks(Process * ProcessObj);

	//Main function of Engine
	void Global_Cks();
	void Main();

};

#endif