#include "Process.h"
#include <sstream>
#include <iostream>
#include <Psapi.h>

Process::Process(std::string Proc) {
	Pinfo = GetProcessInfo(Proc);
	Sleep(1000);

	Modules = ListModulesA(Pinfo.Process_ID, 1);
	Pinfo.ModuleCount = Modules.size();

	Handles = ListHandles(Pinfo.Process_ID);
	Pinfo.HandleCount = Handles.size();
}

Process::~Process(){

}


#pragma optimize("", off)
//Get the Process Information
Process::Process_INFO Process::GetProcessInfo(std::string & PN){
	//Process_INFO Pinfo;
	PVOID buffer = NULL;
	PSYSTEM_PROCESS_INFO inf = NULL;
	LPWSTR ProcNAME;

	//convert CHAR to WCHAR
	/*int nChars = MultiByteToWideChar(CP_ACP, 0, PN, -1, NULL, 0);
	LPWSTR P1 = new WCHAR[nChars];	//Release this at some point
	MultiByteToWideChar(CP_ACP, 0, PN, -1, (LPWSTR)P1, nChars);
	//delete[] P1;
	*/

	ULONG buffer_size = 512 * 512;

	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQuerySystemInformation");


	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL){
		return Pinfo;
	}

	Status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemExtendedProcessInformation, buffer, buffer_size, NULL);

	//if buffer is too small double size
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		buffer_size *= 2;
	}

	else if (!NT_SUCCESS(Status)) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return Pinfo;
	}

	else{
		inf = (PSYSTEM_PROCESS_INFO)buffer;

		while (inf) {
			ProcNAME = inf->ImageName.Buffer;

			if (inf->ImageName.Buffer != nullptr){

				//List of all the process id on the current system
				if (inf->UniqueProcessId > 0){
					System_PID_List.push_back(inf->UniqueProcessId);
				}

				//WinAPI - Converts a Wide Char to multibyte
				int nLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, NULL, NULL, NULL, NULL);
				LPSTR P1 = new CHAR[nLen];
				WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)ProcNAME, -1, P1, nLen, NULL, NULL);
				std::string ProcessName(P1);
				delete[] P1;
				//std::cout << P1 << std::endl;
				//if (strcmp(PN, ProcessName) == 0){
				if (PN.compare(ProcessName) == 0){
					Pinfo.Process_ID = (DWORD)inf->UniqueProcessId;

					Pinfo.Process_Name = ProcessName;
					CHAR szTemp[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", (inf->CreateTime).QuadPart);
					Pinfo.Create_Time = szTemp;
					Pinfo.ThreadCount = inf->NumberOfThreads;
					Pinfo.HandleCount = inf->HandleCount;

					/*FILETIME ft;
					SYSTEMTIME st;
					GetSystemTime(&st);
					SystemTimeToFileTime(&st, &ft);
					LARGE_INTEGER CT = inf->CreateTime;
					CHAR szTemp[MAX_PATH] = { 0 };
					CHAR szTemp1[MAX_PATH] = { 0 };
					sprintf(szTemp, "%I64d", CT.QuadPart);
					sprintf(szTemp1, "%I64d", ft);
					std::cout << szTemp << std::endl;
					std::cout << szTemp1 << std::endl;*/
					//std::cout << PID << std::endl;
					//delete[] P1;

					//return Pinfo;
				}
				//delete[] P1;


				/*//Testing stuff
				if (wcscmp(P1, ProcNAME) == 0){
				PID = (DWORD)inf->UniqueProcessId;
				delete[] P1;
				std::cout << PID << std::endl;
				return PID;
				}*/

			}

			if (!inf->NextEntryOffset)
				break;

			inf = (PSYSTEM_PROCESS_INFO)((LPBYTE)inf + inf->NextEntryOffset);
		}

		if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);
	}

	return Pinfo;
}

All_SYS::PLDR_DATA_TABLE_ENTRY Process::GetNextNode(PCHAR nNode, int Offset){
	nNode -= sizeof(LIST_ENTRY)*Offset;
	return (All_SYS::PLDR_DATA_TABLE_ENTRY)nNode;
}

//List Modules using PBI
//ListType = 0 - InLoadOrderModuleList
//ListType = 1 - InMemoryOrderModuleList
//ListType = 2 - InInitializationOrderModuleList
std::vector < Process::Module_INFO > Process::ListModulesA(DWORD PID, int ListType){
	Process::Module_INFO MD;
	std::vector < Module_INFO > ListOfMods;

	if (ListType > 2 || ListType < 0){
		return ListOfMods;
	}

	PROCESS_BASIC_INFORMATION PBI = { 0 };
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess) GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQueryInformationProcess");

	if (NT_SUCCESS(NtQIP(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
	{
		All_SYS::PEB_LDR_DATA LdrData;
		All_SYS::LDR_DATA_TABLE_ENTRY LdrModule;
		All_SYS::PPEB_LDR_DATA pLdrData = nullptr;
		PBYTE address = nullptr;

		PBYTE LdrDataOffset = (PBYTE)(PBI.PebBaseAddress) + offsetof(struct All_SYS::_PEB, LoaderData);
		ReadProcessMemory(ProcessHandle, LdrDataOffset, &pLdrData, sizeof(All_SYS::PPEB_LDR_DATA), NULL);
		ReadProcessMemory(ProcessHandle, pLdrData, &LdrData, sizeof(All_SYS::PEB_LDR_DATA), NULL);

		if (ListType == 0)
			address = (PBYTE)LdrData.InLoadOrderModuleList.Flink;
		else if (ListType == 1)
			address = (PBYTE)LdrData.InMemoryOrderModuleList.Flink;
		else if (ListType == 2)
			address = (PBYTE)LdrData.InInitializationOrderModuleList.Flink;

		address -= sizeof(LIST_ENTRY)*ListType;

		All_SYS::PLDR_DATA_TABLE_ENTRY Head = (All_SYS::PLDR_DATA_TABLE_ENTRY)address;
		All_SYS::PLDR_DATA_TABLE_ENTRY Node = Head;

		do
		{
			BOOL status = ReadProcessMemory(ProcessHandle, Node, &LdrModule, sizeof(All_SYS::LDR_DATA_TABLE_ENTRY), NULL);
			if (status)
			{

				std::wstring BaseDllName(LdrModule.BaseDllName.Length / sizeof(WCHAR), 0);
				std::wstring FullDllName(LdrModule.FullDllName.Length / sizeof(WCHAR), 0);
				ReadProcessMemory(ProcessHandle, LdrModule.BaseDllName.Buffer, &BaseDllName[0], LdrModule.BaseDllName.Length, NULL);
				ReadProcessMemory(ProcessHandle, LdrModule.FullDllName.Buffer, &FullDllName[0], LdrModule.FullDllName.Length, NULL);

				MD.BaseAddress = LdrModule.BaseAddress;
				MD.EntryPoint = LdrModule.EntryPoint;
				MD.SizeOfImage = LdrModule.SizeOfImage;
				MD.Flags = LdrModule.Flags;
				MD.LoadCount = LdrModule.LoadCount;
				MD.TlsIndex = LdrModule.TlsIndex;
				MD.TimeDateStamp = LdrModule.TimeDateStamp;
				MD.FullDllName = FullDllName;
				MD.BaseDllName = BaseDllName;

				if (LdrModule.BaseAddress != 0) 
				{
					ListOfMods.push_back(MD);
				}

				else{
					break;
				}
			}

			if (ListType == 0)
				Node = GetNextNode((PCHAR)LdrModule.InLoadOrderModuleList.Flink, ListType);
			else if (ListType == 1)
				Node = GetNextNode((PCHAR)LdrModule.InMemoryOrderModuleList.Flink, ListType);
			else if (ListType == 2)
				Node = GetNextNode((PCHAR)LdrModule.InInitializationOrderModuleList.Flink, ListType);

		} while (Head != Node);
	}

	CloseHandle(ProcessHandle);
	return ListOfMods;
}

void Process::BuildModuleArray(All_SYS::PMODULE_LIST pModList){
	DWORD i;
	BOOL retVal;

	for (i = 0; i < pModList->nDLLs; i++){
		DWORD dwBytes;
		All_SYS::MODULEINFO moduleInformation;

		dwBytes = GetModuleFileNameEx(pModList->handle,	pModList->handleDLL[i], pModList->moduleArray[i].fileName, MAX_FILENAME);

		if (dwBytes == 0){
			(pModList->moduleArray[i]).fileName[0] = '\0';
		}

		retVal = GetModuleInformation(pModList->handle, pModList->handleDLL[i], (LPMODULEINFO)&moduleInformation, sizeof(All_SYS::MODULEINFO));

		if (retVal == 0){
			pModList->moduleArray[i].dllInfo.lpBaseOfDll = 0;
			pModList->moduleArray[i].dllInfo.SizeOfImage = 0;
			pModList->moduleArray[i].dllInfo.EntryPoint = 0;
		}
		pModList->moduleArray[i].dllInfo = moduleInformation;
	}
	return;
}

void Process::BuildModuleList(All_SYS::PMODULE_LIST pModList){
	BOOL retVal;
	DWORD dwBytes;

	retVal = EnumProcessModulesEx(pModList->handle, pModList->handleDLL, (DWORD)Max_DLLs*sizeof(HMODULE), &dwBytes, 0x03);

	if (retVal == 0){
		pModList->nDLLs = 0;
		return;
	}

	pModList->nDLLs = dwBytes / sizeof(HMODULE);

	if (pModList->nDLLs > Max_DLLs){
		pModList->nDLLs = 0;
		return;
	}

	pModList->moduleArray = (All_SYS::PMODULE_DATA)malloc(sizeof(All_SYS::MODULE_DATA) * pModList->nDLLs);

	BuildModuleArray(pModList);
	return;
}

//ListModules using Psapi
void Process::ListModulesB(DWORD PID){
	All_SYS::MODULE_LIST ModList;

	HANDLE pHANDLE = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	ModList.handle = pHANDLE;

	BuildModuleList(&ModList);

	std::cout << ModList.nDLLs << std::endl;
	All_SYS::PMODULE_DATA Data = ModList.moduleArray;

	for (int i = 0; i < ModList.nDLLs; i++){
		std::cout << (&Data[i]) -> fileName << " -- Base:" << (&Data[i]) -> dllInfo.lpBaseOfDll << "--" << std::endl;
	}

	CloseHandle(pHANDLE);
	free(ModList.moduleArray);
}

//List the Handles of a process 
std::vector < Process::Handle_INFO > Process::ListHandles(DWORD PID){
	std::vector < Handle_INFO > HandleVec;
	//Handle_INFO HIF;

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQueryObject");

	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID)))
	{
		std::cout << "Can't open " << PID << std::endl;
		return HandleVec;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	// NtQuerySystemInformation won't give us the correct buffer size
	while ((status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH){
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}

	// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
	if (!NT_SUCCESS(status))
	{
		//printf("NtQuerySystemInformation failed!\n");
		std::cout << "NtQuerySystemInformation failed!" << std::endl;
		return HandleVec;
	}

	for (ULONG i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength = 0;

		// Check if this handle belongs to the PID the user specified. 
		
		if (handle.ProcessId != PID)
			continue;
		

		// Duplicate the handle so we can query it.
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle,	GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//std::cout << "[0x" << std::hex << handle.Handle << "] Error! \n";
			continue;
		}

		// Query the object type. 
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo,	0x1000,	NULL)))
		{
			//std::cout << "[0x" << std::hex << handle.Handle << "] Error! \n";
			CloseHandle(dupHandle);
			continue;
		}

		//Named Pipelines Check - cause query to hang
		if (handle.GrantedAccess == 0x0012019f)
		{
			// We have the type, so display that.
			LPSTR P1 = new CHAR[objectTypeInfo->Name.Length];
			WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)objectTypeInfo->Name.Buffer, -1, P1, objectTypeInfo->Name.Length, NULL, NULL);

			HIF.PID = handle.ProcessId;
			HIF.Handle = (DWORD) handle.Handle;
			HIF.ObjectTypeNumber = (DWORD) handle.ObjectTypeNumber;
			HIF.ObjectTypeName = P1;
			HIF.ObjectName = "--Did not get name--";
			HandleVec.push_back(HIF);

			//Handle location
			//std::cout << "[0x" << std::hex << handle.Handle << "] ";
			//std::cout << P1 << ": ";
			//std::cout << "--Did not get name--";
			//std::cout << std::endl;
			//std::cout << (DWORD)handle.ObjectTypeNumber << std::endl;
			delete[] P1;
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);

		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
		{
			//
			if ( !( returnLength >= ULONG_MAX - 100 ) ){
				objectNameInfo = realloc(objectNameInfo, returnLength);
			}

			else{ 
				//If it greater assume returnlength incorrect and allocate 1MB
				objectNameInfo = realloc(objectNameInfo, 0x1000000); 
			}

			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,	objectNameInfo,	returnLength, NULL)))
			{
				// We have the type, so display that.
				LPSTR P1 = new CHAR[objectTypeInfo->Name.Length];
				WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)objectTypeInfo->Name.Buffer, -1, P1, objectTypeInfo->Name.Length, NULL, NULL);

				HIF.PID = handle.ProcessId;
				HIF.Handle = (DWORD) handle.Handle;
				HIF.ObjectTypeNumber = (DWORD)handle.ObjectTypeNumber;
				HIF.ObjectTypeName = P1;
				HIF.ObjectName = "--Could not get name--";
				HandleVec.push_back(HIF);

				//Handle location
				//std::cout << "[0x" << std::hex << handle.Handle << "] ";
				//std::cout << P1 << ": ";
				//std::cout << "--Could not get name--";
				//std::cout << std::endl;
				delete[] P1;
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}

		}

		// Cast our buffer into an UNICODE_STRING
		objectName = *(PUNICODE_STRING)objectNameInfo;

		// Print the information!
		if (objectName.Length)
		{
			// The object has a name. 
			LPSTR P1 = new CHAR[objectTypeInfo->Name.Length];
			WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)objectTypeInfo->Name.Buffer, -1, P1, objectTypeInfo->Name.Length, NULL, NULL);

			LPSTR P2 = new CHAR[objectName.Length];
			WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)objectName.Buffer, -1, P2, objectName.Length, NULL, NULL);

			HIF.PID = handle.ProcessId;
			HIF.Handle = (DWORD)handle.Handle;
			HIF.ObjectTypeNumber = (DWORD)handle.ObjectTypeNumber;
			HIF.ObjectTypeName = P1;
			HIF.ObjectName = P2;
			HandleVec.push_back(HIF);

			//Handle location
			//std::cout << "[0x" << std::hex << handle.Handle << "] ";
			//Handle Type Name
			//std::cout << P1 << ": ";
			//std::cout << P2 << std::endl;
			delete[] P1;
			delete[] P2;
			//Handle Type Number - KEY: 23 / FILE: 1C / DIR: 3 / Event: C / ALPC PORT: 24 / THREAD: 8
			//std::cout << (DWORD)handle.ObjectTypeNumber << std::endl;
		}
		else
		{
			// The object has a name. 
			LPSTR P1 = new CHAR[objectTypeInfo->Name.Length];
			WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)objectTypeInfo->Name.Buffer, -1, P1, objectTypeInfo->Name.Length, NULL, NULL);

			HIF.PID = handle.ProcessId;
			HIF.Handle = (DWORD)handle.Handle;
			HIF.ObjectTypeNumber = (DWORD)handle.ObjectTypeNumber;
			HIF.ObjectTypeName = P1;
			HIF.ObjectName = "--Unnamed--";
			delete[] P1;

			//Get Name of Process for Unnamed process
			if ((DWORD)handle.ObjectTypeNumber == 7){
				//std::cout << (int)handle.Handle << std::endl;
				HANDLE hDup = (HANDLE)handle.Handle;
				HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId);

				if (hProc)
				{
					BOOL b = DuplicateHandle(hProc, (HANDLE)handle.Handle,
						GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
					if (!b)
					{
						hDup = (HANDLE)handle.Handle;
					}
					CloseHandle(hProc);
				}

				LPSTR NameP = new CHAR[MAX_PATH];
				DWORD charsCarried = MAX_PATH;

				//Win32 path format
				if (QueryFullProcessImageName(hDup, 0, NameP, &charsCarried) == 0) {
					//if QueryName fails
					delete[] NameP;
					HIF.ObjectName = "Unknown";
					HandleVec.push_back(HIF);
					if (hDup && (hDup != (HANDLE)handle.Handle))
					{
						CloseHandle(hDup);
					}
					continue;
				}

				//Native system path format
				//QueryFullProcessImageName(hDup, 0x00000001, Test, &charsCarried);
				else{
					char * token = std::strtok(NameP, "\\");
					std::vector<char*> TokenArray;
					TokenArray.push_back(token);

					while (token != NULL) {
						//std::cout << token << '\n';
						token = std::strtok(NULL, "\\");
						if (token != NULL){
							TokenArray.push_back(token);
						}
					}

					//for (unsigned int i = 0; i < TokenArray.size(); i++){
					//	std::cout << TokenArray[i] << std::endl;
					//	}

					HIF.ObjectName = TokenArray[TokenArray.size() - 1];
					//std::cout << TokenArray[TokenArray.size() - 1] << std::endl;;

					TokenArray.clear();
					delete[] NameP;

					if (hDup && (hDup != (HANDLE)handle.Handle))
					{
						CloseHandle(hDup);
					}
				}

			}

			HandleVec.push_back(HIF);

			//Handle location
			//std::cout << "[0x" << std::hex << handle.Handle << "] ";
			//std::cout << P1 << ": ";
			//std::cout << "--Unnamed--";
			//std::cout << std::endl;
			//std::cout << (DWORD)handle.ObjectTypeNumber << std::endl;
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	return HandleVec;
}

void Process::FindModuleFromAddr(DWORD dwPID, std::wstring & wModule, DWORD dwThreadAddr, DWORD * pModStrAddr, int FullPathName)
{
	std::vector < Process::Module_INFO > ProcModules = ListModulesA(dwPID, 1);
	unsigned int i = 0;
	for (i = 0; i < ProcModules.size(); i++){
		if (dwThreadAddr >= (DWORD)ProcModules[i].BaseAddress && dwThreadAddr <= ((DWORD)ProcModules[i].BaseAddress + ProcModules[i].SizeOfImage)){
			if (FullPathName == FALSE){
				wModule = ProcModules[i].BaseDllName;
			}
			else{
				wModule = ProcModules[i].FullDllName;
			}
			break;
		}
	}
	if (pModStrAddr && i != (unsigned int) ProcModules.size())
		*pModStrAddr = (DWORD)ProcModules[i].BaseAddress;
	else
		*pModStrAddr = 0;
}

std::vector < Process::Thread_INFO > Process::ListThreads(DWORD PID){
	std::vector < Thread_INFO > ThreadVec;
	SYSTEM_EXTENDED_THREAD_INFORMATION sExtThreadInfo;
	Thread_INFO sThreadInfo;
	PVOID buffer = NULL;
	PSYSTEM_PROCESS_INFO inf = NULL;

	ULONG buffer_size = 512 * 512;

	NTSTATUS Status = STATUS_INFO_LENGTH_MISMATCH;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQuerySystemInformation");

	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (buffer == NULL){
		return ThreadVec;
	}

	Status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemExtendedProcessInformation, buffer, buffer_size, NULL);

	//if buffer is too small double size
	if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		buffer_size *= 2;
	}

	else if (!NT_SUCCESS(Status)) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return ThreadVec;
	}

	else{
		inf = (PSYSTEM_PROCESS_INFO)buffer;
		std::wstring wModName = L"0";
		std::string sModName = " ";
		DWORD dwModBaseAddr = NULL;
		DWORD dwThreadAddr = NULL;
		HANDLE hThread = NULL;
		std::stringstream stringbuffer;

		while (inf) {
			if ((DWORD)inf->UniqueProcessId == PID){
				//std::cout << inf->NumberOfThreads << std::endl;
				for (DWORD i = 0; i < (DWORD)inf->NumberOfThreads; i++){
					sExtThreadInfo = inf->Threads[i];

					//std::cout << std::dec << (DWORD)sExtThreadInfo.ThreadInfo.ClientId.UniqueThread << std::endl;

					//Win32StartAddress;
					//std::cout << (DWORD)sExtThreadInfo.StartAddress << std::endl;
					dwThreadAddr = (DWORD)sExtThreadInfo.Win32StartAddress;

					//Match the Win32Addr to Module
					FindModuleFromAddr(PID, wModName, dwThreadAddr, &dwModBaseAddr, TRUE);
					sModName = std::string(wModName.begin(), wModName.end());
					stringbuffer << sModName << " + " << "0x" << std::hex << (dwThreadAddr - dwModBaseAddr) << std::dec << std::endl;
					sThreadInfo.FullModPathToAddr = stringbuffer.str();

					//clear buffer
					stringbuffer.str(std::string());

					FindModuleFromAddr(PID, wModName, dwThreadAddr, &dwModBaseAddr, FALSE);
					sModName = std::string(wModName.begin(), wModName.end());
					stringbuffer << sModName << " + " << "0x" << std::hex << (dwThreadAddr - dwModBaseAddr) << std::dec << std::endl;
					sThreadInfo.BaseModPathToAddr = stringbuffer.str();

					sThreadInfo.ExtThreadInfo = sExtThreadInfo;
					ThreadVec.push_back(sThreadInfo);
				}
			}

			if (!inf->NextEntryOffset)
				break;

			inf = (PSYSTEM_PROCESS_INFO)((LPBYTE)inf + inf->NextEntryOffset);
		}

		if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);
	}
	return ThreadVec;
}

//List System Modules and Drivers
std::vector < Process::System_Module_INFO > Process::ListSystemModules(){
	NTSTATUS status;
	PSYSTEM_MODULE_INFORMATION ptrModuleInfo;
	std::vector < System_Module_INFO > sysModVec;
	System_Module_INFO sysMD;
	ULONG buffer_size = 512 * 512;
	PVOID buffer;

	status = STATUS_INFO_LENGTH_MISMATCH;
	_ntQSI fpQSI = (_ntQSI)GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQuerySystemInformation");

	buffer = VirtualAlloc(NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL){
		return sysModVec;
	}

	status = fpQSI((SYSTEM_INFORMATION_CLASS)All_SYS::SystemModuleInformation, buffer, buffer_size, NULL);

	//if buffer is too small double size
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		buffer_size *= 2;
	}

	else if (!NT_SUCCESS(status)) {
		VirtualFree(buffer, NULL, MEM_RELEASE);
		return sysModVec;
	}

	else{
		//Pointer to System Module Information
		ptrModuleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;

		sysMD.ModulesCount = ptrModuleInfo->ModulesCount;

		for (int i = 0; i < ptrModuleInfo->ModulesCount; i++){
			SYSTEM_MODULE sysModule = ptrModuleInfo->Modules[i];
			sysMD.Modules.push_back(sysModule);
		}

		sysModVec.push_back(sysMD);

		if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);
	}
	return sysModVec;
}
#pragma optimize("", on)