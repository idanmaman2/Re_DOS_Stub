#include<windows.h>
#include<iostream>
using namespace std;

char help []  = "DosStub.exe [FilePE] [FileMZ] \n\t* Dos and EXE file merge  \n\t* support all valid PE and MZ\n\t* using dos stub to merge the files ";

int main(int argc, char** argv) {

	if (argc != 3) {
		cerr << help << endl;
		return -1;
	}



	cout << "FILES TO MERGE: " << endl << "\t*PE: " << argv[1] << endl << " \t*MZ: " << argv[2] << endl;
	HANDLE peFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!peFile) {
		cout << GetLastError() << endl;
		exit(-1);
	}

	HANDLE mzFile = CreateFileA(argv[2], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!mzFile) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	IMAGE_DOS_HEADER peDos;
	IMAGE_DOS_HEADER mzDos;
	DWORD readed = 0;
	if (!ReadFile(peFile, &peDos, sizeof(IMAGE_DOS_HEADER), &readed, NULL) || readed != sizeof(IMAGE_DOS_HEADER)) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	if (peDos.e_magic != 0x5A4d) {
		cout << "not a valid file";
		exit(-1);
	}
	readed = 0;
	if (!ReadFile(mzFile, &mzDos, sizeof(IMAGE_DOS_HEADER), &readed, NULL) || readed != sizeof(IMAGE_DOS_HEADER)) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	if (mzDos.e_magic != 0x5A4d) {
		cout << "not a valid file";
		exit(-1);
	}
	puts("\n ---- PE - DOS PROGRAM ---- \n ");

	DWORD dosStubCurrentSize = peDos.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	char* dosStub = new char[dosStubCurrentSize];
	if (!ReadFile(peFile, dosStub, dosStubCurrentSize, &readed, NULL) || readed != dosStubCurrentSize) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	for (int i = 0; i < dosStubCurrentSize; cout << hex << (int)dosStub[i++]);
	puts("\n");
	for (int i = 0; i < dosStubCurrentSize; cout << dosStub[i++]);
	puts("\n\n ---- MZ - DOS PROGRAM ---- \n ");
	DWORD dosProgramSize = GetFileSize(mzFile, NULL) - sizeof(IMAGE_DOS_HEADER);
	char* dosProgram = new char[dosProgramSize];
	if (!ReadFile(mzFile, dosProgram, dosProgramSize, &readed, NULL) || readed != dosProgramSize) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	for (int i = 0; i < dosProgramSize; cout << hex << (int)dosProgram[i++]);
	puts("\n");
	for (int i = 0; i < dosProgramSize; cout << dosProgram[i++]);

	CloseHandle(mzFile);

	IMAGE_NT_HEADERS peNT; 
	if (!ReadFile(peFile, &peNT, sizeof(IMAGE_NT_HEADERS), &readed, NULL) || readed != sizeof(IMAGE_NT_HEADERS)) {
		cout << GetLastError() << endl;
		exit(-1);
	}
	if (peNT.Signature != IMAGE_NT_SIGNATURE) {
		cout << "Signutare is not valid" << endl;
		exit(-1);
	}

	cout << peNT.OptionalHeader.ImageBase << endl; 

	CloseHandle(peFile);

	return 0;


}