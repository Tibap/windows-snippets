/*
* @author: Tibap
* Functions to :
*  - list all modules in a process
*  - list all processes
*  - search for all docx in specific folder
*/

#include <windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <TlHelp32.h>

using namespace std;

void print_help(WCHAR* prog) {
	wprintf(TEXT("%s [ 1 \"directory\" | 2 | 3 ]\n"), prog);
}


bool listDocx(wstring folder) {
	WIN32_FIND_DATA FileData;
	HANDLE hfind;

	//wcout << "Listing files in: " << folder << endl;
	wstring files = folder + L"\\*";

	hfind = FindFirstFile(files.c_str(), &FileData);
	if (hfind == INVALID_HANDLE_VALUE) {
		//wcout << "Path not found: " << folder << endl;
		return false;
	}
	do {
		if (wcscmp(FileData.cFileName, L".") != 0 && wcscmp(FileData.cFileName, L"..") != 0){
			wstring path = folder + L"\\\\" + FileData.cFileName;

			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_VIRTUAL ||
				FileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				//wcout << "Found specific file: " << path << endl;
				//Deal with specific file here if needed...
				continue;
			}

			if (FileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				//wcout << "Found directory: " << filename << endl;
				listDocx(path);
			}
			else {
				//wcout << "Found file: " << path << endl;

				if (path.substr(path.length() - 5) == L".docx") {
					wcout << "Found docx file: " << path << endl;
					SYSTEMTIME stCreation;
					FileTimeToSystemTime(&FileData.ftCreationTime, &stCreation);
					SYSTEMTIME stModif;
					FileTimeToSystemTime(&FileData.ftLastWriteTime, &stModif);

					wcout << "INFO: " << endl;
					wcout << "  Filename: " << FileData.cFileName << endl;
					wcout << "  Alternate filename: " << FileData.cAlternateFileName << endl;
					//Calculated size is from msdn...
					wcout << "  Size: " << (FileData.nFileSizeHigh * (MAXDWORD + 1)) + FileData.nFileSizeLow
						<< " bytes" << endl;
					wcout << "  Creation time: " << stCreation.wYear << ":" <<
						stCreation.wMonth << ":" <<
						stCreation.wDay << " " << stCreation.wHour << "H" <<
						stCreation.wMinute << "M" << endl;
					wcout << "  Modification time: " << stModif.wYear << ":" <<
						stModif.wMonth << ":" <<
						stModif.wDay << " " << stModif.wHour << "H" << stModif.wMinute <<
						"m" << endl;

				}
			}
		}

	} while (FindNextFile(hfind, &FileData) != 0);

	if (GetLastError() != ERROR_NO_MORE_FILES) {
		wcout << "Error: " << GetLastError() << endl;
	}

	//wcout << "Closing handle to: " << files << endl;
	FindClose(hfind);
	return true;
}

bool listModules(DWORD pid) {

	MODULEENTRY32 module_entry;
	HANDLE hSnap;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		//wcout << "Invalid handle value" << endl;
		if (GetLastError() == ERROR_ACCESS_DENIED) {
			wcout << "  Access to modules is protected by the system" << endl;
			return true;
		}
		else {
			wcout << "Unknown error: " << GetLastError() << endl;
		}
		return false;
	}

	// Set size of process entry
	module_entry.dwSize = sizeof(MODULEENTRY32);

	if (! Module32First(hSnap, &module_entry)) {
		wcout << "Failed to get module info of process." << endl;
		CloseHandle(hSnap);
		return false;
	}
	do {
		wcout << "  Module name: " << module_entry.szModule << endl;
		wcout << "    Module path: " << module_entry.szExePath << endl;
		wcout << "    Module base address: " << module_entry.modBaseAddr << endl;
		wcout << "    Module size: " << module_entry.modBaseSize << endl;
	} while (Module32Next(hSnap, &module_entry));

	if (GetLastError() != ERROR_NO_MORE_FILES) {
		wcout << "Error: " << GetLastError() << endl;
		CloseHandle(hSnap);
		return false;
	}
	CloseHandle(hSnap);
	return true;
}

void listProcesses() {
	HANDLE hSnap;
	PROCESSENTRY32 process_info;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		wcout << "Invalid handle value" << endl;
		return;
	}

	wcout << "Getting process info..." << endl;

	// Set size of process entry
	process_info.dwSize = sizeof(PROCESSENTRY32);

	if (! Process32First(hSnap, &process_info)) {
		wcout << "Failed to get process info of process." << endl;
		CloseHandle(hSnap);
		return;
	}
	do {
		// Print process info and modules info
		wcout << endl;
		wcout << "Process name: " << process_info.szExeFile << endl;
		wcout << "  Process ID: " << process_info.th32ProcessID << endl;
		wcout << "  Parent ID: " << process_info.th32ParentProcessID << endl;
		wcout << "  Nb threads: " << process_info.cntThreads << endl;
		if (! listModules(process_info.th32ProcessID)) {
			wcout << "  Something went wrong when listing modules..." << endl;
		}

	} while (Process32Next(hSnap, &process_info));

	if (GetLastError() != ERROR_NO_MORE_FILES) {
		wcout << "Error: " << GetLastError() << endl;
	}
	CloseHandle(hSnap);
}

int listAutostartExe() {
	//wcout << "Not finished yet" << endl;
	HKEY hkey = NULL;
	WCHAR* runkey = TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	WCHAR name [255];
	DWORD index = 0;
	DWORD nb_subkeys, nb_values;
	DWORD cbname, cbvalue;
	FILETIME time_str;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, runkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
		wprintf(TEXT("Error opening key: %s\n"), runkey);
		return -1;
	}
	wprintf(TEXT("Enumerating registry key: %s -- DOES NOT WORK FOR NOW.\n"), runkey);

	if (hkey == NULL) {
		wprintf(TEXT("Hkey is NULL, something's wrong.\n"));
		return -1;
	}

	if (RegQueryInfoKeyW(hkey, NULL, NULL, NULL, &nb_subkeys,
		NULL, NULL, &nb_values, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
		wprintf(TEXT("Cannot query info for key %s. Error: %d\n"), runkey, GetLastError());
		RegCloseKey(hkey);
		return -1;
	}

	if (nb_subkeys > 0) {
		wprintf(TEXT("Enumerating subkeys (%d)...\n"), nb_subkeys);
		cbname = 255;
		for (DWORD i=0; i<nb_subkeys; i++){
			if (RegEnumKeyEx(hkey, i, name, &cbname, NULL, NULL, NULL, &time_str) == ERROR_SUCCESS) {
				wprintf(TEXT("Found: %s\n"), name);
			}
			else {
				wprintf(TEXT("Error: %d\n"), GetLastError());
			}
		}
	}

	if (nb_values > 0) {
		WCHAR value_name [16383];
		DWORD len_name = 0;
		cbvalue = 16383;

		wprintf(TEXT("Enumerating key values (%d)...\n"), nb_values);
		for (unsigned int i = 0; i < nb_values; i++) {
			if (RegEnumKey(hkey, i, value_name, len_name) == ERROR_SUCCESS) {
				wprintf(TEXT("Value: %s\n"), value_name);
			}

		}
	}
	if (nb_subkeys == 0 && nb_values == 0) {
		wprintf(TEXT("Registry key seems empty\n"));
	}

	RegCloseKey(hkey);
	return 0;
}


int wmain(int argc, WCHAR* argv[])
{
	WCHAR* prog_name = TEXT("");
	WCHAR* param2 = TEXT("");
	WCHAR* folder = TEXT("");

	if (argc < 2) {
		prog_name = argv[0];
		wprintf(TEXT("%s: do not have correct parameters.\n"), prog_name);
		print_help(prog_name);
		return -1;
	}
	int param = stoi(argv[1]);

	switch (param) {
	case 1:
		if (argc != 3) {
			print_help(argv[0]);
			return -1;
		}
		folder = argv[2];
		wprintf(TEXT("List all docx files in folder: \"%s\"\n"), folder);
		system("pause");
		listDocx(folder);
		break;
	case 2:
		wcout << "List all process with their modules." << endl;
		listProcesses();
		break;
	case 3:
		wcout << "List all executables launched at boot." << endl;
		listAutostartExe();
		break;
	default:
		wcout << "Unknown parameter: " << param << endl;
		print_help(argv[0]);
	}
    return 0;
}
