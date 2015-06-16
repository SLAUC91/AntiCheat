#ifndef __PScanner_H__
#define __PScanner_H__

#define NULL 0
typedef unsigned char BYTE;
typedef BYTE * PBYTE;
typedef unsigned long DWORD;
typedef char * PCHAR;

class PScanner{
private:
	bool CompareData(PBYTE pData, PBYTE seqSignature, PCHAR seqMask);

public:
	PScanner();
	~PScanner();

	PBYTE FindPattern(PBYTE dwAddr, DWORD dwSize, PBYTE seqSignature, PCHAR seqMask);
};

#endif