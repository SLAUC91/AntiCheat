/**
Driver For AntiCheat.
This is a x32 driver will be converted to a x64 driver
and communication framework will be developed soon.
*/

#include <ntddk.h>
#include <wdf.h>
#include <windef.h>
#include <Ntstrsafe.h>

//Certain Warnings disabled
#pragma warning(disable:4055)
#pragma warning(disable:4214) 
#pragma warning(disable:4100) 
#pragma warning(disable:4200) 

#define NTOSKRNL_BASE "\\SystemRoot\\system32\\ntkrnlpa.exe"	//Kernel
#define SystemModuleInformation 11	//QSI
#define SIZE_F 256					//FileSize
#define SYSTEM_SERVICE_VECTOR 0x2E	//Int2E
#define IA32_SYSENTER_EIP 0x176		//MSR

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI * _zwQSI)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI * _KeSetAffinityThread)(
	PKTHREAD pKThread,
	KAFFINITY cpuAffinityMask
);

#pragma paxk(1)
typedef struct _IDT_DESCRIPTOR{
	WORD offset00_15;	//Bits [00,15] Offset addr bits
	WORD selector;		//Bits [16,31] Segment Selector
	BYTE unused : 5;	//Bits [0,4] Not Used
	BYTE zeros : 3;		//Bits [5,7] Should all be zero
	BYTE gateType : 5;	//Bits [8,12] Interrupt (01110), Trap (01111)
	BYTE DPL : 2;		//Bits [13,14] DPL - Descriptor Privilege Level
	BYTE P : 1;			//Bits [15,15] Segment Present Flag (set)
	WORD offset16_31;	//Bits [16,32] Offset addr bits
}IDT_DESCRIPTOR, *PIDT_DESCRIPTOR;
#pragma pack()

#pragma paxk(1)
typedef struct _IDTR{
	WORD nBytes;		//Size Limit
	WORD baseAddrLow;
	WORD baseAddrHi;
}IDTR;
#pragma pack()

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PVOID Base;					//Base Adr
	ULONG Size;					//Size 
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[SIZE_F];	//Name of module

}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _MODULE_ARRAY
{
	int	nModules;
	SYSTEM_MODULE_INFORMATION element[];
}MODULE_ARRAY, *PMODULE_ARRAY;

typedef struct _MSR {
	UINT32 value_low;
	UINT32 value_high;
} MSR, *PMSR;

#pragma pack(1)
typedef struct ServiceDescriptorEntry{
	DWORD *KiServiceTable;		//SSDT entry 
	DWORD *CounterBaseTable;
	DWORD nSystemCalls;			//nElements SSDT
	DWORD *KiArgumentTable;
}SDE, *PSDE;
#pragma pack()

PMODULE_ARRAY getModuleArray(){
	//Technically you don't need the casts but helps for clearty

	DWORD nBytes = 0;
	PMODULE_ARRAY modArray = NULL;
	NTSTATUS ntStatus;
	UNICODE_STRING FName;
	_zwQSI fpQSI;	//Function pointer to ZwQuerySystemInformation

	RtlInitUnicodeString(&FName, L"ZwQuerySystemInformation");
	fpQSI = (_zwQSI)MmGetSystemRoutineAddress(&FName);

	SYSTEM_INFORMATION_CLASS ID = (SYSTEM_INFORMATION_CLASS)SystemModuleInformation;

	fpQSI(ID, &nBytes, 0, &nBytes);

	modArray = (PMODULE_ARRAY)ExAllocatePool(PagedPool, nBytes);
	if (modArray == NULL){
		return NULL;
	}

	ntStatus = fpQSI(ID, modArray, nBytes, 0);

	if (!NT_SUCCESS(ntStatus)){
		ExFreePool(modArray);
		return NULL;
	}

	return modArray;
}

void GetMSRAddress(UINT32 reg, MSR * msraddr) {
	//MSR msraddr;
	UINT32 lowvalue = 0;
	UINT32 highvalue = 0;

	// Get address of the IDT table
	// Can't do in line asm on x64
	__asm {
		push eax;
		push ecx;
		push edx;
		mov ecx, reg;
		rdmsr;
		mov lowvalue, eax;
		mov highvalue, edx;
		pop edx;
		pop ecx;
		pop eax;
	}

	msraddr->value_low = lowvalue;
	msraddr->value_high = highvalue;
	DbgPrint("Address of MSR entry %x is: %x.\r\n", reg, msraddr);
}

//Check A Single MSR
void CheckOneMSR(PSYSTEM_MODULE_INFORMATION mod){
	MSR msr;
	DWORD start;
	DWORD end;

	start = (DWORD)mod->Base;
	end = (start + mod->Size) - 1;
	DbgPrint("CheckOneMSR: Module start= %08x\t end=%08x\n", start, end);

	GetMSRAddress(IA32_SYSENTER_EIP, &msr);
	DbgPrint("CheckOneMSR: MSR Value = {%08x}", msr.value_low);

	if ((msr.value_low < start) || (msr.value_low > end)){
		DbgPrint("CheckOneMSR: MSR Out Of Range");
	}
	return;
}

//Check CPU MSRs for every Processor
void CheckAllMSR(PSYSTEM_MODULE_INFORMATION mod){
	KAFFINITY cpuBitMap;
	PKTHREAD pKThread;
	DWORD i = 0;
	UNICODE_STRING procName;
	_KeSetAffinityThread KeSetAff;

	RtlUnicodeStringInit(&procName, L"KeSetAffinityThread");
	KeSetAff = (_KeSetAffinityThread)MmGetSystemRoutineAddress(&procName);

	cpuBitMap = KeQueryActiveProcessors();
	pKThread = KeGetCurrentThread();

	DbgPrint("CheckAllMSRs: Checking ALL CPUs!");

	//Keep in mind that this may not be accurate for hot swap CPUs
	//Will add better support in future 
	DWORD nCPU = 32; //32 for x32 - 64 fpr x64

	for (i = 0; i < nCPU; i++){
		KAFFINITY currentCPU = cpuBitMap & (1 << i);
		if (currentCPU != 0){
			DbgPrint("CheckALLMSR: CPU {%u} ", i);
			KeSetAff(pKThread, currentCPU);
			CheckOneMSR(mod);
		}
	}

	KeSetAff(pKThread, cpuBitMap);
	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

DWORD makeDWORD(WORD hi, WORD lo){
	DWORD value;
	value = 0;
	value = value | (DWORD)hi;
	value = value << 16;
	value = value | (DWORD)lo;
	return value;
}

//Int2E Single checks
void CheckOneInt2E(PSYSTEM_MODULE_INFORMATION mod){
	PIDT_DESCRIPTOR idt;
	DWORD addressISR;
	DWORD start;
	DWORD end;
	IDTR idtr;

	start = (DWORD)mod->Base;
	end = (start + mod->Size) - 1;
	DbgPrint("CheckOneInt2E: Module start = {%08x}\tend = {%08x}\n", start, end);

	__asm{
		cli;
		sidt idtr;
		sti;
	}

	idt = (PIDT_DESCRIPTOR)makeDWORD(idtr.baseAddrHi, idtr.baseAddrLow);
	addressISR = makeDWORD(idt[SYSTEM_SERVICE_VECTOR].offset16_31, idt[SYSTEM_SERVICE_VECTOR].offset00_15);

	DbgPrint("CheckOneInt2E: Addr = {%08x}", addressISR);
	
	if ((addressISR < start) || (addressISR > end)){
		DbgPrint("CheckOneInt2E: MSR Out of Range!");
	}
	return;
}

//Check All Int2E for every Processor
void CheckAllInt2E(PSYSTEM_MODULE_INFORMATION mod){
	KAFFINITY cpuBitMap;
	PKTHREAD pKThread;
	DWORD i = 0;
	UNICODE_STRING procName;
	_KeSetAffinityThread KeSetAff;

	RtlUnicodeStringInit(&procName, L"KeSetAffinityThread");
	KeSetAff = (_KeSetAffinityThread)MmGetSystemRoutineAddress(&procName);

	cpuBitMap = KeQueryActiveProcessors();
	pKThread = KeGetCurrentThread();

	DbgPrint("CheckAllInt2E: Checking ALL CPUs!");

	//Keep in mind that this may not be accurate for hot swap CPUs
	//Will add better support in future 
	DWORD nCPU = 32; //32 for x32 - 64 fpr x64

	for (i = 0; i < nCPU; i++){
		KAFFINITY currentCPU = cpuBitMap & (1 << i);
		if (currentCPU != 0){
			DbgPrint("CheckAllInt2E: CPU {%u} ", i);
			KeSetAff(pKThread, currentCPU);
			CheckOneInt2E(mod);
		}
	}

	KeSetAff(pKThread, cpuBitMap);
	PsTerminateSystemThread(STATUS_SUCCESS);
	return;
}

__declspec (dllimport) SDE KeServiceDescriptorTable;

//Check the SSDT for out of range module
void CheckSSDT(SYSTEM_MODULE_INFORMATION mod){
	DWORD * ssdt;
	DWORD nCalls;
	DWORD i;
	DWORD start;
	DWORD end;

	start = (DWORD)mod.Base;
	end = (start + mod.Size) - 1;
	ssdt = (DWORD*)KeServiceDescriptorTable.KiServiceTable;
	nCalls = KeServiceDescriptorTable.nSystemCalls;

	for (i = 0; i < nCalls; i++, ssdt++){
		DbgPrint("CheckSSDT: call {%03u} = %08x\n", i, *ssdt);
		if ((*ssdt < start) || (*ssdt >end)){
			DbgPrint("CheckSSDT: SSDT Entry Out Of Range");
		}
	}
	return;
}

//Check Single Driver IRP Handler
void CheckDriver(SYSTEM_MODULE_INFORMATION mod, WCHAR* Name){

	PFILE_OBJECT	hookFile;
	PDEVICE_OBJECT	hookDevice;
	PDRIVER_OBJECT	hookDriver;

	NTSTATUS status;
	UNICODE_STRING deviceName;
	DWORD i;
	DWORD start;
	DWORD end;

	start = (DWORD) mod.Base;
	end = (start + mod.Size) - 1;
	DbgPrint("DriverCheck: MOD Start: = %08x\tend = %08x\n", start, end);

	RtlUnicodeStringInit(&deviceName, Name);

	status = IoGetDeviceObjectPointer(&deviceName, FILE_READ_DATA, &hookFile, &hookDevice);

	if (!NT_SUCCESS(status)){
		DbgPrint("Failed to get Device Object Ptr");
		return;
	}

	DbgPrint("Device Object Ptr - Success");
	hookDriver = hookDevice->DriverObject;

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++){
		DWORD addr = (DWORD)(hookDriver->MajorFunction[i]);
		if ((addr < start) || (addr > end)){
			if (addr){
				DbgPrint("CheckDriver: IRP %03u = %08x Not In Range", i, addr);
			}
			else{
				DbgPrint("CheckDriver: IRP %03u = NULL", i);
			}
		}
		else{
			DbgPrint("CheckDriver: IRP %03u = %08x Valid", i, addr);
		}
	}
	return;
}

PSYSTEM_MODULE_INFORMATION GetModuleInformation(char * imageName, PMODULE_ARRAY mod){
	int i;
	for (i = 0; i < mod->nModules; i++){
		if (strcmp(imageName, (mod->element[i]).ImageName) == 0){
			return &(mod->element[i]);
		}
	}
	return NULL;
}

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD KmdfEvtDeviceAdd;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	PMODULE_ARRAY pModArray = NULL;
	PSYSTEM_MODULE_INFORMATION pModule;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "STATUS: DriverEntry\n"));

	pModArray = getModuleArray();

	if (pModArray != NULL){

		//Get Kernel Base
		//pModule = &pMod->element[0];	//ntkrnlpa is the first element
		pModule = GetModuleInformation(NTOSKRNL_BASE, pModArray);
	
		if (pModule != NULL){
			//Check MSRs
			CheckAllMSR(pModule);

			//Check Int2E
			CheckAllInt2E(pModule);

			//Check SSDT
			CheckSSDT(*pModule);

			//Check IRP
			//TODO:Change to Test all Drivers
			char * imageName = "test.sys";
			WCHAR DeviceNameA[] = L"\\test";
			pModule = GetModuleInformation(imageName, pModArray);
			CheckDriver(*pModule, DeviceNameA);

			//ExFreePool(pModArray);
		}
	}
	return STATUS_SUCCESS;
}