#include "Engine.h"
#include "pScanner.h"
#include <unordered_map>

// Directory Entries
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0 // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1 // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE   2 // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5 // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG      6 // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_TLS        9 // TLS Directory


#define BUFFER_SIZE (1024 * 1024)
HANDLE drive = nullptr;
USN maxusn;
std::unordered_map<PVOID, int> AddrHashCount;
//Engine::PeInfo ProcessFunctionInfo;

Engine::Engine(std::string Proc){
	PreLoaderINFO = new Process(Proc);
	ProcN = Proc;

}

Engine::~Engine(){
	delete PreLoaderINFO;
}

std::wstring Engine::s2ws(const std::string & s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	std::wstring r(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, &r[0], len);
	return r;
}

std::string Engine::ws2s(const std::wstring & s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0);
	std::string r(len, '\0');
	WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, &r[0], len, 0, 0);
	return r;
}

int Engine::GetPrcessorInfo(){
	SYSTEM_INFO stInfo;
	//GetSystemInfo(&stInfo);

	GetNativeSystemInfo(&stInfo);

	switch (stInfo.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		//printf("Processor Architecture: Intel x86\n");
		return 0;
		break;
	case PROCESSOR_ARCHITECTURE_IA64:
		//printf("Processor Type: Intel x64\n");
		return 6;
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		//printf("Processor Type: AMD 64\n");
		return 9;
		break;
	default:
		//printf("Unknown processor architecture\n");
		return -1;
	}
}

void Engine::CompareModules(Process * A, Process * B){
	//Unknown Module List
	std::vector<Process::Module_INFO> CU_List;

	bool Found = FALSE;
	//Compare Module Base Name and Image Size
	for (unsigned int i = 0; i < B->Modules.size(); i++){
		
		for (unsigned int j = 0; j < A->Modules.size(); j++){
		
			//Check if name match with the same image size
			if ( ((B->Modules[i].BaseDllName).compare(A->Modules[j].BaseDllName) == 0) && (B->Modules[i].SizeOfImage == A->Modules[j].SizeOfImage) ){
				Found = TRUE;
				break;
			}

		}

		//If not found in A
		if (Found == FALSE){
			CU_List.push_back(B->Modules[i]);
		}
		else{
			Found = FALSE;
		}
	}

	//Determine if we need to send data to server
	if (CU_List.size() != 0){
		
		if (Send_MOD_List.size() == CU_List.size()){
			//List are the same
		}

		else{
			//TODO::SEND THE CHANGED MODULE LIST BUFFER TO SERVER
			Send_MOD_List = CU_List;

			bool status = Send_Object(Send_MOD_List);

			//Test - Print module list
			//for (int i = 0; i < Send_MOD_List.size(); i++){
			//	std::wcout << Send_MOD_List[i].BaseDllName << std::endl;
			//}


			//std::cout << "--------------------------------------\n"; 

		}

	}
}

//Compares the modules in the PEB to the modules paged into memory 
void Engine::CompareModulesPEBtoVQ(Process * Proc){
	bool dllFound = false;
	PVOID baseaddr = 0;

	for (int i = 0; i < Proc->Pages.size(); i++){
		dllFound = false;
		//if the page is not a Mem_Image skip
		if (!(Proc->Pages[i].isDLLpage)){
			continue;
		}

		//Check if we already checked the address 
		if ((PVOID)Proc->Pages[i].memInfo.AllocationBase == baseaddr){
			continue;
		}

		//Page is Mem_Image
		for (int j = 0; j < Proc->Modules.size(); j++){
			//Check if the Base addr is in PEB struct == allocation base addr
			PVOID BaseAlloc = (PVOID)Proc->Pages[i].memInfo.AllocationBase;
			PVOID ModBaseAddr = Proc->Modules[j].BaseAddress;
			if (BaseAlloc == ModBaseAddr){
				dllFound = true;
				baseaddr = BaseAlloc;
				break;
			}

		}

		//AllocationBase Zero
		if (Proc->Pages[i].memInfo.AllocationBase == 0){ 
			continue; 
		}

		//DLL not found in PEB
		if (!dllFound){
			baseaddr = (PVOID)Proc->Pages[i].memInfo.AllocationBase;
			PVOID PageBase = (PVOID) Proc->Pages[i].memInfo.BaseAddress;
			if (baseaddr != PageBase){
				//If you hit here then that means that the DLL
				//was in the page list and not PEB
				std::wcout << baseaddr << " " << PageBase << " " << Proc->Pages[i].nativeFullNameMem << std::endl;
			}
		}

	}
}

//Check if the virtual pages were spilt
void Engine::CheckSegmentCount(Process * Proc, BOOL initalized){
	DWORD count = 1;
	for (int i = 0; i < Proc->Pages.size() - 1; i++){

		if ((PVOID)Proc->Pages[i].memInfo.AllocationBase == (PVOID)Proc->Pages[i + 1].memInfo.AllocationBase){
			count++;
		}

		//skip if the allocation base is zero
		else if ((PVOID)Proc->Pages[i].memInfo.AllocationBase == 0){
			continue;
		}

		else{
			if (initalized){
				int countInHash = AddrHashCount.at((PVOID)Proc->Pages[i].memInfo.AllocationBase);

				if (countInHash == count){
					continue;
				}
				else{
					std::cout << "-----Page Split-----" << std::endl;
					std::wcout << "Alloc Addr: " << (PVOID)Proc->Pages[i - 1].memInfo.AllocationBase << " " << Proc->Pages[i - 1].nativeFullNameMem << std::endl;
					std::pair<PVOID, int> element((PVOID)Proc->Pages[i].memInfo.AllocationBase, count);
					AddrHashCount.insert(element);
					count = 1;
				}
			}
			else{
				std::pair<PVOID, int> element((PVOID)Proc->Pages[i].memInfo.AllocationBase, count);
				AddrHashCount.insert(element);
				count = 1;
			}
		}
	}
}

void ScanPages(){

}

void Engine::show_record(USN_RECORD * record)
{
	void * buffer;
	MFT_ENUM_DATA mft_enum_data;
	DWORD bytecount = 1;
	USN_RECORD * parent_record;

	WCHAR * filename;
	WCHAR * filenameend;
	
	printf("RecordLength: %u\n", record->RecordLength);
	printf("MajorVersion: %u\n", (DWORD)record->MajorVersion);
	printf("MinorVersion: %u\n", (DWORD)record->MinorVersion);
	printf("FileReferenceNumber: %lu\n", record->FileReferenceNumber);
	printf("ParentFRN: %lu\n", record->ParentFileReferenceNumber);
	printf("USN: %lu\n", record->Usn);
	printf("Timestamp: %lu\n", record->TimeStamp);
	printf("Reason: %u\n", record->Reason);
	printf("SourceInfo: %u\n", record->SourceInfo);
	printf("SecurityId: %u\n", record->SecurityId);
	printf("FileAttributes: %x\n", record->FileAttributes);
	printf("FileNameLength: %u\n", (DWORD)record->FileNameLength);

	filename = (WCHAR *)(((BYTE *)record) + record->FileNameOffset);
	filenameend = (WCHAR *)(((BYTE *)record) + record->FileNameOffset + record->FileNameLength);

	printf("FileName: %.*ls\n", filenameend - filename, filename);

	buffer = VirtualAlloc(NULL, BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (buffer == NULL)
	{
		return;
	}

	mft_enum_data.StartFileReferenceNumber = record->ParentFileReferenceNumber;
	mft_enum_data.LowUsn = 0;
	mft_enum_data.HighUsn = maxusn;

	if (!DeviceIoControl(drive, FSCTL_ENUM_USN_DATA, &mft_enum_data, sizeof(mft_enum_data), buffer, BUFFER_SIZE, &bytecount, NULL))
	{
		return;
	}

	parent_record = (USN_RECORD *)((USN *)buffer + 1);

	if (parent_record->FileReferenceNumber != record->ParentFileReferenceNumber)
	{
		return;
	}

	show_record(parent_record);
}

bool Engine::check_record(USN_RECORD * record, std::wstring s_filename)
{
	WCHAR * filename;
	WCHAR * filenameend;

	filename = (WCHAR *)(((BYTE *)record) + record->FileNameOffset);
	filenameend = (WCHAR *)(((BYTE *)record) + record->FileNameOffset + record->FileNameLength);

	if (filenameend - filename != 8) return FALSE;

	int buffer = s_filename.length();
	const wchar_t * wc_filename = s_filename.c_str();

	if (wcsncmp(filename, wc_filename, buffer) != 0) return FALSE;

	//show_record(record);
	return TRUE;
}

//Returns a record matching qurey or null pointer
USN_RECORD * Engine::GetUSN(std::wstring & CheckFor){
	MFT_ENUM_DATA mft_enum_data;
	DWORD bytecount = 1;
	void * buffer;
	USN_RECORD * record;
	USN_RECORD * recordend;
	USN_JOURNAL_DATA * journal;
	DWORDLONG nextid;
	DWORDLONG filecount = 0;

	buffer = VirtualAlloc(NULL, BUFFER_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (buffer == NULL)
	{
		//printf("VirtualAlloc: %u\n", GetLastError());
		return nullptr;
	}

	//TODO: CHECK ALL NTFS DRIVES
	drive = CreateFile("\\\\?\\C:", GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING, NULL);

	if (drive == INVALID_HANDLE_VALUE)
	{
		//printf("CreateFile: %u\n", GetLastError());
		return nullptr;
	}

	if (!DeviceIoControl(drive, FSCTL_QUERY_USN_JOURNAL, NULL, 0, buffer, BUFFER_SIZE, &bytecount, NULL))
	{
		//printf("FSCTL_QUERY_USN_JOURNAL: %u\n", GetLastError());
		return nullptr;
	}

	journal = (USN_JOURNAL_DATA *)buffer;

	//printf("UsnJournalID: %lu\n", journal->UsnJournalID);
	//printf("FirstUsn: %lu\n", journal->FirstUsn);
	//printf("NextUsn: %lu\n", journal->NextUsn);
	//printf("LowestValidUsn: %lu\n", journal->LowestValidUsn);
	//printf("MaxUsn: %lu\n", journal->MaxUsn);
	//printf("MaximumSize: %lu\n", journal->MaximumSize);
	//printf("AllocationDelta: %lu\n", journal->AllocationDelta);

	maxusn = journal->MaxUsn;

	mft_enum_data.StartFileReferenceNumber = 0;
	mft_enum_data.LowUsn = 0;
	mft_enum_data.HighUsn = maxusn;

	//FSCTL_ENUM_USN_DATA
	for (;;)
	{

		if (!DeviceIoControl(drive, FSCTL_ENUM_USN_DATA, &mft_enum_data, sizeof(mft_enum_data), buffer, BUFFER_SIZE, &bytecount, NULL))
		{
			//printf("FSCTL_ENUM_USN_DATA: %u\n", GetLastError());
			//printf("Final ID: %lu\n", nextid);
			//printf("File count: %lu\n", filecount);
			return nullptr;
		}

		nextid = *((DWORDLONG *)buffer);
		record = (USN_RECORD *)((USN *)buffer + 1);
		recordend = (USN_RECORD *)(((BYTE *)buffer) + bytecount);

		while (record < recordend)
		{
			filecount++;
			if (check_record(record, CheckFor)) { return record; };
			//show_record(record);
			record = (USN_RECORD *)(((BYTE *)record) + record->RecordLength);
		}

		mft_enum_data.StartFileReferenceNumber = nextid;
	}

	if (buffer) VirtualFree(buffer, NULL, MEM_RELEASE);

	return nullptr;
}

//Returns a record matching qurey or null pointer
DNSCACHEENTRY * Engine::GetDNS(std::wstring & s_filename){
	DNSCACHEENTRY * pEntry = (PDNSCACHEENTRY)malloc(sizeof(DNSCACHEENTRY));

	// Loading DLL not a commonly Loaded DLL
	HINSTANCE hLib = LoadLibrary(TEXT("DNSAPI.dll"));

	// Get function address
	DNS_GET_CACHE_DATA_TABLE DnsGetCacheDataTable = (DNS_GET_CACHE_DATA_TABLE)GetProcAddress(hLib, "DnsGetCacheDataTable");

	int status = DnsGetCacheDataTable(pEntry);
	pEntry = pEntry->pNext;


	while (pEntry) {
		//Use DnsQuery function to get ip and ttl
		//wprintf(L"%s : %d\n", (pEntry->pszName), (pEntry->wType));

		//check for specific website
		if (wcscmp(pEntry->pszName, s_filename.c_str()) == 0){
			wprintf(L"%s \n", (pEntry->pszName));
			return pEntry;
		}

		pEntry = pEntry->pNext;
	}

	free(pEntry);
	return nullptr;
}

//Check for any open handles to our process
void Engine::Check_Handles(Process * Proc){

	std::vector < Process::Handle_INFO > Temp_Data;

	//Send a list of process handle originating from your process
	//Proc->ListHandles(Proc->Pinfo.Process_ID);

	//std::cout << Proc->System_PID_List.size() << std::endl;
	
	//Check the handles for every process on the system
	for (unsigned int i = 0; i < Proc->System_PID_List.size(); i++){
		Temp_Data = Proc->ListHandles(Proc->System_PID_List[i]);

		for (unsigned int j = 0; j < Temp_Data.size(); j++){
			//Check if a process is opening a handle to out process
			if (Temp_Data[j].ObjectTypeNumber == 7 && (Temp_Data[j].ObjectName.compare(ProcN) == 0)){
				std::cout << Temp_Data[j].PID << " ";
				std::cout << Temp_Data[j].ObjectTypeName << ": " << Temp_Data[j].ObjectName << std::endl;
				PID_H.push_back(Temp_Data[j].PID);
			}
		}
		Temp_Data.clear();
	}
}

//Check for thread injection in our process particularly threads created with CreateRemoteThread()
//TODO: hook LoadLibrary
void Engine::Check_Threads(Process * Proc){
	//Vector to the Injected threads
	std::vector<Process::Thread_INFO> vecInjectedThread;
	DWORD dwThreadPID = 0;

	for (unsigned i = 0; i < Proc->Threads.size(); i++){
		dwThreadPID = (DWORD) (Proc->Threads[i]).ExtThreadInfo.ThreadInfo.ClientId.UniqueProcess;
		//check if Threads PID does not match our process pid 
		if (dwThreadPID != Proc->Pinfo.Process_ID){
			vecInjectedThread.push_back(Proc->Threads[i]);
		}
		//check if the Thread is in the Process address space
		else if (Proc->ThreadInAddrModList(Proc->Threads[i].ExtThreadInfo)){
			vecInjectedThread.push_back(Proc->Threads[i]);
		}
	}

}

PIMAGE_SECTION_HEADER ImageRVA2Section(IMAGE_NT_HEADERS * pImage_NT_Headers, DWORD dwRVA)
{
	IMAGE_SECTION_HEADER * pISH = (IMAGE_SECTION_HEADER *)(((BYTE *)pImage_NT_Headers) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < pImage_NT_Headers->FileHeader.NumberOfSections; i++)
	{
		
		if ((pISH->VirtualAddress) && (dwRVA <= (pISH->VirtualAddress + pISH->SizeOfRawData)))
		{
			return (PIMAGE_SECTION_HEADER) pISH;
		}

		pISH++;
	}
	return nullptr;
}

DWORD RVA2Offset(void * pImageBase, DWORD dwRVA)
{
	DWORD offset;
	PIMAGE_SECTION_HEADER section;
	PIMAGE_DOS_HEADER pimage_dos_header;
	PIMAGE_NT_HEADERS pimage_nt_headers;
	pimage_dos_header = PIMAGE_DOS_HEADER(pImageBase);
	pimage_nt_headers = (PIMAGE_NT_HEADERS)( ((SIZE_T)pimage_dos_header) + pimage_dos_header -> e_lfanew);
	section = ImageRVA2Section(pimage_nt_headers, dwRVA);
	if (section == nullptr)
	{
		return 0;
	}
	offset = dwRVA + section->PointerToRawData - section->VirtualAddress;
	return offset;
}

void Engine::GetPeInfo(std::string FilePath){
	//PeInfo ProcessFunctionInfo;
	//PEFunctions Functions;
	//DLLcontainer cDLL;

	IMAGE_DOS_HEADER*       pDosHeader;
	IMAGE_NT_HEADERS*       pNtHeaders;
	//IMAGE_SECTION_HEADER*   pSectionHeader;
	PIMAGE_IMPORT_DESCRIPTOR	pImageImportData;
	//PIMAGE_THUNK_DATA			pImageThunkData;
	PIMAGE_EXPORT_DIRECTORY		pImageExportData;

	ProcessFunctionInfo.Name = FilePath;
	ProcessFunctionInfo.Func = &Functions;

	void * FileHandle = CreateFile(FilePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	
	if (FileHandle == INVALID_HANDLE_VALUE) 
		return;

	void * FileMapping = CreateFileMapping(FileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
	void * MapView = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);

	pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(MapView);
	pNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(((SIZE_T)(pDosHeader)) + pDosHeader->e_lfanew);

	//Export Directory parsing

	DWORD dwExportDirectory = RVA2Offset(MapView, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (dwExportDirectory == 0)
	{
		return;
	}

	pImageExportData = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)MapView + dwExportDirectory);

	ULONG *addressoffunctions = (ULONG*)((BYTE*)pDosHeader + pImageExportData->AddressOfFunctions);
	ULONG * addressofnames = (ULONG*)((BYTE*)pDosHeader + pImageExportData->AddressOfNames);

	for (DWORD x = 0; x < pImageExportData -> NumberOfFunctions; x++)
	{
		//printf("%s\n", (BYTE*)pDosHeader + addressofnames[x]);
		char buffer[MAX_PATH];
		sprintf(buffer, "%s", (BYTE*)pDosHeader + addressofnames[x]);
		ProcessFunctionInfo.Func->ExpFuncVec.push_back(buffer);
	}

	//Print Export Vector
	//for (int i = 0; i < ProcessFunctionInfo.Func->ExpFuncVec.size(); i++){
		//std::cout << ProcessFunctionInfo.Func->ExpFuncVec[i] << std::endl;
	//}

	//End Export Directory

	//Import Directory Parsing
	DWORD dwImportDirectory = RVA2Offset(MapView, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	pImageImportData = (PIMAGE_IMPORT_DESCRIPTOR)( (BYTE*)MapView + dwImportDirectory);

	//void * pThunk;
	//void * dwThunk;
	void * pDllName;
	PBYTE pTDATA;
	PBYTE pThunk;
	PBYTE dwThunk;
	PBYTE pAPIName;

	DWORD		dwAPIaddress;

//	PIMAGE_THUNK_DATA thunkILT;
//	PIMAGE_THUNK_DATA thunkIAT;

	while (pImageImportData->Characteristics != 0)
	{
		pThunk = (PBYTE)MapView + pImageImportData->FirstThunk;
		dwThunk = (PBYTE)pImageImportData->FirstThunk;

		pTDATA = (PBYTE)MapView;

		//thunkILT = (PIMAGE_THUNK_DATA)pImageImportData->OriginalFirstThunk;
		//thunkIAT = (PIMAGE_THUNK_DATA)pImageImportData->FirstThunk;
		
		if (pImageImportData->OriginalFirstThunk != 0)
		{
			//thunkILT
			pTDATA += RVA2Offset(MapView, pImageImportData->OriginalFirstThunk);
		}
		else
		{
			//thunkIAT
			pTDATA += RVA2Offset(MapView, pImageImportData->FirstThunk);
		}

		pDllName = (BYTE*)MapView + RVA2Offset(MapView, pImageImportData->Name);
		//printf(" DLL Name: %s First Thunk: 0x%x \n\n", pDllName, pImageImportData->FirstThunk);
		char buffer[MAX_PATH];
		sprintf(buffer, "%s", pDllName);
		cDLL.Name = buffer;

		PIMAGE_THUNK_DATA pimage_thunk_data = (PIMAGE_THUNK_DATA)pTDATA;

		while (pimage_thunk_data->u1.AddressOfData != 0){
			dwAPIaddress = pimage_thunk_data->u1.AddressOfData;
			if ((dwAPIaddress & IMAGE_ORDINAL_FLAG) == IMAGE_ORDINAL_FLAG)
			{
				//OrdinalFunctions - Don't include in our struct
				dwAPIaddress &= 0x7FFFFFFF;
				//printf("Proccess: 0x%x \n", dwAPIaddress);
				//char buffer[MAX_PATH];
				//sprintf(buffer, "0x%x", dwAPIaddress);
				//cDLL.ImpFuncVec.push_back(buffer);
			}
			else
			{
				//Access the IMAGE_IMPORT_BY_NAME struct
				//skip WORD Hint and get the Name pointer
				pAPIName = (BYTE*)MapView + RVA2Offset(MapView, dwAPIaddress) + sizeof(WORD);
				//printf("Proccess: %s\n", pAPIName);
				char buffer[MAX_PATH];
				sprintf(buffer, "%s", pAPIName);
				cDLL.ImpFuncVec.push_back(buffer);
			}
			pThunk += 4;
			pTDATA += 4;
			pimage_thunk_data++;
		}

		Functions.ImpDllVec.push_back(cDLL);

		pImageImportData++;
	}

	UnmapViewOfFile(MapView);
	CloseHandle(FileMapping);
	CloseHandle(FileHandle);

}

//Checks all the DLL's functions for suspicious import or export functions
void Engine::DLL_Cks(Process * ProcessObj){
	//Check if DLL is flagged then check for suspicious import or export functions
	for (unsigned int i = 0; i < ProcessObj->Modules.size(); i++){
			std::string NameOf = ws2s(ProcessObj->Modules[i].FullDllName);
			GetPeInfo(NameOf);
			//Check ProcessFunctionInfo
	}

	//Check the send list for suspicious import or export functions
	for (unsigned int j = 0; j < Send_MOD_List.size(); j++){
		if (Send_MOD_List[j].FullDllName.size() == NULL){
			//Flag it - This should never occur unless the DLL
			//is loaded from memory instead of the disk
		}
		else {
			std::string NameOf = ws2s(Send_MOD_List[j].FullDllName);
			GetPeInfo(NameOf);
			//Check ProcessFunctionInfo
		}
	}

	return;
}

//Check these only once at the start
void Engine::Global_Cks(){
	Process * RT_ActionRunner = new Process(ProcN);

	//Check for 64 bit system
	int ProcessorType = GetPrcessorInfo();
	if (ProcessorType == 0 || ProcessorType == -1){
		///Termminate Client & program
		//HANDLE C = OpenProcess(PROCESS_TERMINATE, FALSE, PreLoaderINFO->Pinfo.Process_ID);
		//TerminateProcess(C, NULL);
		//exit(0);
	}

	//Check USN 
	//std::wstring Test0 = L"TEST.exe";
	//USN_RECORD * usn_record = GetUSN(Test0);

	//Check DNS
	//std::wstring Test1 = L"www.test.com";
	//DNSCACHEENTRY * dns_record = GetDNS(Test1);

	HANDLE Query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, RT_ActionRunner->Pinfo.Process_ID);

	LPSTR NameP = new CHAR[MAX_PATH];
	DWORD charsCarried = MAX_PATH;

	//Win32 path format
	if (QueryFullProcessImageName(Query, 0, NameP, &charsCarried) == 0) {
		//Check the executable file
		GetPeInfo(NameP);
	}

	CloseHandle(Query);
	delete[] NameP;

	//Create hash
	CheckSegmentCount(RT_ActionRunner, FALSE);

	delete RT_ActionRunner;

	return;
}

void Engine::Main(){

	//Run our checking loop
	while (true){
		//Get the object
		Process * RT_ActionRunner = new Process(ProcN);

		//MODULE checks
		//If fails flag it
		CompareModules(PreLoaderINFO, RT_ActionRunner);

		//Change module list varient
		//Check for strange function imports or exports
		DLL_Cks(RT_ActionRunner);

		//Handle Checks 
		Check_Handles(RT_ActionRunner);

		//Check Threads
		Check_Threads(RT_ActionRunner);

		CompareModulesPEBtoVQ(RT_ActionRunner);
		
		CheckSegmentCount(RT_ActionRunner, TRUE);

		delete RT_ActionRunner;
		
		//Scan interval every 5 sec
		Sleep(5000);
	}

}