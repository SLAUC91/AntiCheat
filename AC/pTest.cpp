#include <Windows.h>
#include <iostream>
#include <assert.h>
#include "Engine.h"
#include "pTest.h"

pTest::pTest(){}

pTest::~pTest(){}

void pTest::printModulesA(Process * A){
	//Modules
	std::vector < Process::Module_INFO > B = A->ListModulesA(A->Pinfo.Process_ID, 0);
	for (unsigned int i = 0; i < (unsigned int)B.size(); i++){
		std::wcout << B[i].BaseDllName << " \t\t";
		std::cout << "Base Addr: " << std::hex << (DWORD) B[i].BaseAddress << " Entry: " << (DWORD) B[i].EntryPoint << std::endl;
	}
	return;
}

void pTest::printModulesB(Process * A){
	//Modules
	A->ListModulesB(A->Pinfo.Process_ID);
	return;
}

void pTest::printHandles(Process * A){
	//Hanldes
	std::vector < Process::Handle_INFO > C = A->ListHandles(A->Pinfo.Process_ID);
	for (unsigned int i = 0; i < C.size(); i++){
		std::cout << "Handles: " << (DWORD) C[i].Handle << " Type: " << C[i].ObjectTypeName << " Name: " << C[i].ObjectName << std::endl;
	}
	return;
}

void pTest::printThreads(Process * A){
	std::vector < Process::Thread_INFO > D = A->ListThreads(A->Pinfo.Process_ID);

	for (unsigned int i = 0; i < D.size(); i++){
		std::cout << "Thread ID: " << (DWORD)D[i].ExtThreadInfo.ThreadInfo.ClientId.UniqueThread << " ";
		//std::cout << "Win32Addr: " << D[i].Win32Address << std::endl;
		std::cout << "Start Addr: " << D[i].BaseModPathToAddr << std::endl;
	}
	return;
}

void pTest::printSystemModules(Process * A){
	std::vector < Process::System_Module_INFO > ModINFO = A->ListSystemModules();

	//ModINFO.size() should always be one
	for (int i = 0; i < ModINFO.size(); i++)
	{
		for (int j = 0; j < ModINFO[i].ModulesCount; j++){
			std::cout << ModINFO[i].Modules[j].FullPathName + ModINFO[i].Modules[j].OffsetToFileName;
			std::cout << " \tBase: " << ModINFO[i].Modules[j].ImageBase << std::endl;
		}
	}

}

//Test main
void pTest::Tmain(){
	Process *  A = new Process("firefox.exe");

	printModulesA(A);
	//printModulesB(A);
	//printHandles(A);
	//printThreads(A);
	//printSystemModules(A);

	delete A;
}