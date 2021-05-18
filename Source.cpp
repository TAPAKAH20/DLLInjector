#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <winternl.h>
#include <psapi.h>
#include "Remote.h"


#define IF_FAIL_GO(err, func, hand) \
			err = func; \
			if(err != 0) goto hand;

#define IF_FAIL_RET(err, func) \
			err = func; \
			if(err != 0) return err;

//Error code is 0
#define IF_FAIL_RET_NZ_SUCCSESS(err, func) \
			err = func; \
			if(err == 0) return err;

DWORD CreateProc(LPCTSTR appName, HANDLE& hProc, HANDLE& hThread) {

	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};

	if (!CreateProcess(appName,	nullptr, nullptr, nullptr, true, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		DWORD err = GetLastError();
		_tprintf(_T("CreateProcess failed with code 0x%x"), err);
		return err;
	}

	Sleep(1000);

	hProc = pi.hProcess;
	hThread = pi.hThread;

	return ERROR_SUCCESS;
}


DWORD LoopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR& addressOfEntry, WORD& originalEntry) {
	DWORD eStatus = ERROR_SUCCESS;
	PROCESS_BASIC_INFORMATION pbi = {};
	ULONG retLen = 0;
	PEB peb = {}; //defined in Remote.h, ReversedPEB (from nirsoft)
	IMAGE_DOS_HEADER imageDosHeader = {};
	IMAGE_NT_HEADERS imageNtHeader = {};
	WORD patchedEntry = 0xFEEB; // jmp -2

	

	NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLen);

	if (!NT_SUCCESS(status)) {
		_tprintf(_T("NtQueryInformationProcess failed with code 0x%x"), status);
		return status;
	}


	
	//Read PEB
	IF_FAIL_RET(eStatus, ReadRemote<PEB>(hProc, (ULONG_PTR)pbi.PebBaseAddress, peb));
	ULONG_PTR pRemoteBaseAddress = (ULONG_PTR)peb.Reserved3[1];

	// Read Dos Header
	IF_FAIL_RET(eStatus, ReadRemote<IMAGE_DOS_HEADER>(hProc, pRemoteBaseAddress, imageDosHeader));
	// Read NT Header
	IF_FAIL_RET(eStatus, ReadRemote<IMAGE_NT_HEADERS>(hProc, pRemoteBaseAddress + imageDosHeader.e_lfanew, imageNtHeader));
	
	addressOfEntry = (ULONG_PTR)pRemoteBaseAddress + imageNtHeader.OptionalHeader.AddressOfEntryPoint;

	
	// Override entry 
	IF_FAIL_RET(eStatus, ReadRemote<WORD>(hProc, addressOfEntry, originalEntry)); 
	IF_FAIL_RET(eStatus, WriteRemote<WORD>(hProc, addressOfEntry, patchedEntry));

	//Start thread and wait
	ResumeThread(hThread);
	Sleep(1000);

	return 0;
}

// Defined in ntdll
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtSuspendProcess(HANDLE proc);
extern "C" NTSYSCALLAPI NTSTATUS NTAPI NtResumeProcess(HANDLE proc);

DWORD DeLoopEntry(HANDLE hProc, HANDLE hThread, ULONG_PTR addressOfEntry, WORD originalEntry) {

	//Stop execution
	NtSuspendProcess(hProc);
	//Patch
	DWORD eStatus = ERROR_SUCCESS;
	IF_FAIL_RET(eStatus, WriteRemote<WORD>(hProc, addressOfEntry, originalEntry));

	//Resume process
	NtResumeProcess(hProc);

	Sleep(1000);
	
	
	return 0;
}


DWORD FindLoadLibrary(HANDLE hProc, HANDLE hThread, ULONG_PTR& loadLibAddr) {
	LPCSTR targetLib = "KERNEL32.dll";
	LPCSTR targetFunc = "LoadLibraryW";

	HMODULE* hModules = nullptr;
	DWORD needed = 0;
	DWORD size = 0;
	DWORD amount = 0;

	DWORD eStatus = ERROR_SUCCESS;

	//Get modeles size in bytes
	IF_FAIL_RET_NZ_SUCCSESS(eStatus, EnumProcessModules(hProc, nullptr, 0, &needed));

	size = needed;
	amount = size / sizeof(HMODULE);

	hModules = (HMODULE*)malloc(size); //memory leak, if failed before found LoadLibrary()
	if (hModules == nullptr) {
		return 1;
	}

	//Get modules
	IF_FAIL_RET_NZ_SUCCSESS(eStatus, EnumProcessModules(hProc, hModules, size, &needed));

	for (DWORD i = 0; i < amount; i++) {
		ULONG_PTR moduleBase = (ULONG_PTR)hModules[i];
		IMAGE_DOS_HEADER imageDosHeader = {};
		IMAGE_NT_HEADERS imageNtHeader = {};

		// Read Dos and Nt headers
		IF_FAIL_RET(eStatus, ReadRemote<IMAGE_DOS_HEADER>(hProc, moduleBase, imageDosHeader));
		IF_FAIL_RET(eStatus, ReadRemote<IMAGE_NT_HEADERS32>(hProc, moduleBase + imageDosHeader.e_lfanew, imageNtHeader));

		IMAGE_DATA_DIRECTORY exportDir = imageNtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (exportDir.Size == 0) continue; //skip empty exports

		IMAGE_EXPORT_DIRECTORY moduleExport = {};
		IF_FAIL_RET(eStatus, ReadRemote<IMAGE_EXPORT_DIRECTORY>(hProc, moduleBase + exportDir.VirtualAddress, moduleExport));


		CHAR moduleName[MAX_PATH];
		DWORD moduleNameLen = 0;

		IF_FAIL_RET(eStatus, ReadRemote<CHAR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.Name), moduleName, moduleNameLen));


		//if moduleName == targetLib
		if (strcmp(moduleName, targetLib) == 0) {
			DWORD numOfFuncs = moduleExport.NumberOfFunctions;
			DWORD tempNumOfFuncs = numOfFuncs;

			ULONG_PTR* functionNamesRVA = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numOfFuncs);//memory leak, if failed before found LoadLibrary()
			ULONG_PTR* functionAddrsRVA = (ULONG_PTR*)malloc(sizeof(ULONG_PTR) * numOfFuncs);//memory leak, if failed before found LoadLibrary()

			if (functionNamesRVA == nullptr || functionAddrsRVA == nullptr) {
				return 1;
			}

			IF_FAIL_RET(eStatus, ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.AddressOfNames), functionNamesRVA, tempNumOfFuncs));
			IF_FAIL_RET(eStatus, ReadRemote<ULONG_PTR>(hProc, (ULONG_PTR)(moduleBase + moduleExport.AddressOfFunctions), functionAddrsRVA, tempNumOfFuncs));

			for (DWORD j = 0; j < numOfFuncs; j++) {
				CHAR functionName[MAX_PATH];
				DWORD moduleNameLen = 0;

				IF_FAIL_RET(eStatus, ReadRemote<CHAR>(hProc, (ULONG_PTR)(moduleBase + functionNamesRVA[j]), functionName, moduleNameLen));

				if (strcmp(functionName, targetFunc) == 0) {
					loadLibAddr = moduleBase + functionAddrsRVA[j];
					break;
				}
			}


			free(functionNamesRVA);
			free(functionAddrsRVA);
			break;
		}
	}
	free(hModules);

	return 0;
}


DWORD Inject(HANDLE hProc, HANDLE hThread, ULONG_PTR loadLibAddr, WCHAR* dllPath) {
	// shellcode
	UCHAR shellx86[] =
	{
		/*0x00*/	0x6A, 0x00, 0x6A, 0x00,					//
		/*0x04*/	0x68, 0x00, 0x00, 0x00, 0x00,			// push string
		/*0x09*/	0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,		// call loadlibrary
		/*0x0F*/	0xF7, 0xD8,								// neg eax
		/*0x11*/	0x1B, 0xC0,								// sbb eax, eax
		/*0x13*/	0xF7, 0xD8,								// 
		/*0x15*/	0x48,									// 
		/*0x16*/	0xC3,									// ret
		/*0x17*/	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		/*0x20*/	0x00, 0x00, 0x00, 0x00,					// loadlibrary address
		/*0x24*/	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,//alignment
		/*0x30*/	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 256 Bytes of memory
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	
	DWORD status = ERROR_SUCCESS;
		
	// remote alloc
	PVOID pShellRemote = VirtualAllocEx(hProc, nullptr, sizeof(shellx86), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pShellRemote == nullptr) {
		_tprintf(_T("VirtualAllocEx failed"));
		return 1;
	}
	ULONG_PTR remoteShellBase = (ULONG_PTR)pShellRemote;

	ULONG_PTR remoteStringOffset = remoteShellBase + 0x30;
	ULONG_PTR remotePointerOffset = remoteShellBase + 0x20;

	//fill in real values
	memcpy(shellx86 + 0x20, &loadLibAddr, sizeof(ULONG_PTR));
	memcpy(shellx86 + 0x5, &remoteStringOffset, sizeof(ULONG_PTR));
	memcpy(shellx86 + 0x0B, &remotePointerOffset, sizeof(ULONG_PTR));
	memcpy(shellx86 + 0x30, dllPath, 256);

	// 1. address of load library 
	// 2. offset to string
	// 3. 
	

	// move memory
	WriteProcessMemory(hProc, pShellRemote, shellx86, sizeof(shellx86), nullptr);
	// create thread entry at shellcode 
	DWORD tid;
	HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, LPTHREAD_START_ROUTINE(remoteShellBase), nullptr, 0, &tid);
	if (hRemoteThread == NULL) {
		_tprintf(_T("CreateRemoteThread failed"));
		return 1;
	}
	WaitForSingleObject(hRemoteThread, INFINITE);

	DWORD exitCode = 0xF;
	GetExitCodeThread(hRemoteThread, &exitCode);
	
	CloseHandle(hRemoteThread);
	// execute

	return 0;
}

int main(int argc, char* const argv[]) 
{


	LPCTSTR appName = _T("C:\\Users\\R0ACH\\source\\repos\\DX11_Compute_Tutorial\\DX11_Compute_Tutorial-master\\Debug\\DX11_Compute_Tutorial.exe");
	WCHAR dllPath[] = L"C:\\Users\\R0ACH\\source\\repos\\DLL injectable\\Debug\\DLL injectable.dll";
	HANDLE hProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	ULONG_PTR addresOfEntry = 0;
	WORD originalEntry = 0;
	ULONG_PTR loadLibAddr = 0;

	DWORD status = ERROR_SUCCESS;


	//Create process suspended
	IF_FAIL_GO(status, CreateProc(appName, hProc, hThread), MAIN_ERROR_HANDLER);
	_tprintf(_T("Process %s created\n"), appName);

	//Loop entry
	IF_FAIL_GO(status, LoopEntry(hProc, hThread, addresOfEntry, originalEntry), MAIN_ERROR_HANDLER);
	_tprintf(_T("Entry point 0x%x looped \t original code 0x%x\n"), addresOfEntry, originalEntry);

	//Find LoadLibrary
	IF_FAIL_GO(status, FindLoadLibrary(hProc, hThread, loadLibAddr), MAIN_ERROR_HANDLER);
	_tprintf(_T("LoadLibrary() found at 0x%x\n"), loadLibAddr);

	//Inject
	IF_FAIL_GO(status, Inject(hProc, hThread, loadLibAddr, dllPath), MAIN_ERROR_HANDLER);
	_tprintf(_T("DLL injected\n"));

	//Restore entry

	IF_FAIL_GO(status, DeLoopEntry(hProc, hThread, addresOfEntry, originalEntry), MAIN_ERROR_HANDLER);
	_tprintf(_T("Entry restored\n "));

	return 0;
MAIN_ERROR_HANDLER:
	return status;
}