#include "PScanner.h"

PScanner::PScanner(){}
PScanner::~PScanner(){}

bool PScanner::CompareData(PBYTE pData, PBYTE seqSignature, PCHAR seqMask){
	while ((*seqMask) != NULL){
		if (*pData != *seqSignature && *seqMask == 'x')
			return false;
		pData++;
		seqSignature++;
		seqMask++;
	}
	return true;
}

PBYTE PScanner::FindPattern(PBYTE dwAddr, DWORD dwSize, PBYTE seqSignature, PCHAR seqMask){
	DWORD i;
	for (i = 0; i < dwSize; i++)
	{
		if (CompareData(dwAddr + i, seqSignature, seqMask)){
			return (dwAddr + i);
		}
	}
	return nullptr;
}