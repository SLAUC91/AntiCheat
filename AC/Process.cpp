#include "Process.h"

//HANDLE hPROC = NULL;
//DWORD PID_DW = 0;

Process::Process(std::string Proc) {
	Pinfo = GetProcessInfo(Proc);
	Sleep(1000);

	Modules = ListModules(Pinfo.Process_ID);
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


	buffer = VirtualAlloc(NULL, 1048576, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (buffer == NULL){
		return Pinfo;
	}

	SYSTEM_INFORMATION_CLASS ID = (SYSTEM_INFORMATION_CLASS)SystemExtendedProcessInformation;

	Status = fpQSI(ID, buffer, buffer_size, &buffer_size);

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

					//Check if the Process is x32 if so since our process is x64
					//it needs to get the InheritedPID
					if ((DWORD)inf->UniqueProcessId == 0){
						Pinfo.Process_ID = (DWORD)inf->InheritedFromUniqueProcessId;
					}
					else{
						Pinfo.Process_ID = (DWORD)inf->UniqueProcessId;
					}

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

//List Modules using LDR_MODULE
std::vector < Process::Module_INFO > Process::ListModules(DWORD PID){
	Process::Module_INFO MD;
	std::vector < Module_INFO > ListOfMods;

	SIZE_T dwBytesRead = 0;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, PID);

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess) GetProcAddress(GetModuleHandle(("ntdll.dll")), "NtQueryInformationProcess");

	if (NT_SUCCESS(NtQIP(ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PBI), reinterpret_cast<DWORD*>(&dwBytesRead))))
	{
		Process::PEB_LDR_DATA LdrData;
		LDR_MODULE LdrModule;
		Process::PPEB_LDR_DATA pLdrData = nullptr;

		char* LdrDataOffset = reinterpret_cast<char*>(PBI.PebBaseAddress) + offsetof(PEB, Ldr);
		ReadProcessMemory(ProcessHandle, LdrDataOffset, &pLdrData, sizeof(pLdrData), &dwBytesRead);
		ReadProcessMemory(ProcessHandle, pLdrData, &LdrData, sizeof(LdrData), &dwBytesRead);

		//std::cout <<LdrData.Length << "\n";
		LIST_ENTRY* Head = LdrData.InMemoryOrderModuleList.Flink;
		LIST_ENTRY* Node = Head;

		do //LDR_MODULE struct
		{
			if (ReadProcessMemory(ProcessHandle, reinterpret_cast<char*>(Node)-sizeof(LIST_ENTRY), &LdrModule, sizeof(LdrModule), &dwBytesRead))
			{

				std::wstring BaseDllName(LdrModule.BaseDllName.Length / sizeof(WCHAR), 0);
				std::wstring FullDllName(LdrModule.FullDllName.Length / sizeof(WCHAR), 0);
				ReadProcessMemory(ProcessHandle, LdrModule.BaseDllName.Buffer, &BaseDllName[0], LdrModule.BaseDllName.Length, &dwBytesRead);
				ReadProcessMemory(ProcessHandle, LdrModule.FullDllName.Buffer, &FullDllName[0], LdrModule.FullDllName.Length, &dwBytesRead);

				MD.BaseAddress = LdrModule.BaseAddress;
				MD.BaseDllName = BaseDllName;
				MD.EntryPoint = LdrModule.EntryPoint;
				MD.FullDllName = FullDllName;
				MD.LoadCount = LdrModule.LoadCount;
				MD.SizeOfImage = LdrModule.SizeOfImage;
				MD.TimeDateStamp = LdrModule.TimeDateStamp;

				if (LdrModule.BaseAddress) 
				{
					MD.Dll_Flagged = FALSE;
					ListOfMods.push_back(MD);
				}

				else if (LdrModule.BaseAddress == 0){
					//Flag the module - this should not occur unless the call table is changed
					MD.Dll_Flagged = TRUE;
					ListOfMods.push_back(MD);
				}
			}

			Node = LdrModule.InMemoryOrderModuleList.Flink;
		} while (Head != Node);
	}
	CloseHandle(ProcessHandle);
	return ListOfMods;
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
		//printf("Could not open PID %d! (Don't try to open a system process.)\n", PID);
		std::cout << "Can't open " << PID << std::endl;
		return HandleVec;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	/* NtQuerySystemInformation won't give us the correct buffer size,
	so we guess by doubling the buffer size. */
	while ((status = fpQSI(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH){
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
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

		/* Check if this handle belongs to the PID the user specified. */
		
		if (handle.ProcessId != PID)
			continue;
		

		/* Duplicate the handle so we can query it. */
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle,	GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//std::cout << "[0x" << std::hex << handle.Handle << "] Error! \n";
			continue;
		}

		/* Query the object type. */
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

		/* Print the information! */
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

					/*for (unsigned int i = 0; i < TokenArray.size(); i++){
						std::cout << TokenArray[i] << std::endl;
						}*/

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
#pragma optimize("", on)