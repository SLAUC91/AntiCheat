#include <Windows.h>
#include <iostream>
#include <assert.h>
#include "Engine.h"
#include "pTest.h"

pTest::pTest(){}

pTest::~pTest(){}

void pTest::printModules(Process * A){
	//Modules
	std::vector < Process::Module_INFO > B = A->ListModules(A->Pinfo.Process_ID);
	for (unsigned int i = 0; i < (unsigned int)B.size(); i++){
		std::wcout << B[i].BaseDllName << " \t\t";
		std::cout << "Base Addr: " << std::hex << (DWORD) B[i].BaseAddress << " Entry: " << (DWORD) B[i].EntryPoint << std::endl;
	}
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
		std::cout << "Thread ID: " << (DWORD)D[i].ThreadInfo.ClientId.UniqueThread << " ";
		//std::cout << "Win32Addr: " << D[i].Win32Address << std::endl;
		std::cout << "Start Addr: " << D[i].BaseModPathToAddr << std::endl;
	}
	return;
}

//Test main
void pTest::Tmain(){
	Process *  A = new Process("firefox.exe");

	//printModules(A);
	//printHandles(A);
	printThreads(A);

	delete A;
}