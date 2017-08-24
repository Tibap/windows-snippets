/**
 * @author Tibap
 * DLL that hooks calls to FindNextFile within a 32 bits process.
 */

#include <stdio.h>
#include <Windows.h>

// Typedef the function prototype. Otherwise the compiler could mix up between calling conventions
typedef BOOL (WINAPI* _realFunc)(HANDLE h, LPWIN32_FIND_DATA find_data);

LPVOID next_file_addr = NULL;
DWORD old_protect = 0;
LPVOID trampoline_addr = NULL;

// Save address in variable realFunction
_realFunc realFunction = NULL;
BOOL hidding = FALSE;

BOOL WINAPI MyNextFile(HANDLE h, LPWIN32_FIND_DATA find_data) {
	BOOL res;

	// First  call the real FindNextFile function
	res = realFunction(h, find_data);

	if (hidding) {
		// Return FALSE so the entire folder will be hidden
		hidding = FALSE;
		return FALSE;
	}

	// Check if we scan the test dir
	if (wcscmp(find_data->cFileName, TEXT("test")) == 0) {
		// If yes, set hidding to true
		if (find_data->dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
			hidding = TRUE;
		}
	}

	return res;

}

BOOL APIENTRY DllMain(HMODULE hMOdule, DWORD reasonForCall, LPVOID lpreservered) {

	switch (reasonForCall)
	{
	case DLL_PROCESS_ATTACH:
		// Install hook on attach
		MessageBox(NULL, TEXT("Found FindNextFile address"), NULL, NULL);

		// Get FindNextFileW address from module
		next_file_addr = (LPVOID)GetProcAddress(GetModuleHandleW(L"KernelBase.dll"), "FindNextFileW");
		if (next_file_addr == NULL) {
			MessageBox(NULL, TEXT("Did not find FindNextFileW..."), NULL, NULL);
			break;
		}

		// Save adresse of real function so we can jmp back on it
		realFunction = (_realFunc)((DWORD)next_file_addr + 2);

		//MessageBox(NULL, "Found FindNextFile address", NULL, NULL);

		// Get address where to write our jmp near instructions (5 bytes long)
		// Change rights with VirtualProtect so we write and execute it
		trampoline_addr = (BYTE*)next_file_addr - 5;

		if (!VirtualProtect(trampoline_addr, 7, PAGE_EXECUTE_READWRITE, &old_protect)) {
			MessageBox(NULL, TEXT("VirtualProtect failed"), NULL, NULL);
			CloseHandle(next_file_addr);
			break;
		}
		//MessageBox(NULL, "VirtualProtect succeeded.", NULL, NULL);

		// Write jmp -6 instruction (which will replace "mov edi, edi")
		memcpy(next_file_addr, "\xEB\xF9", 2);
		//MessageBox(NULL, "JMP -6 DONE", NULL, NULL);

		// Write the call near instructions at address "trampoline" (either with memcpy...
		memcpy(trampoline_addr, "\xE9", 1);
		// Equivalent should be: *(BYTE*)(trampoline_addr) = 0xE9;


		// ... or directly to the address).
		// Careful with the casts ! (DWORD could be reverted if cast is wrong).
		*(DWORD*)((BYTE*)trampoline_addr + 1) = (DWORD)MyNextFile - (DWORD)trampoline_addr - 5;

		//MessageBox(NULL, "Checkout in debugger !", NULL, NULL);
		wprintf(TEXT("Injected in process.\n"));
		break;

	case DLL_PROCESS_DETACH:
		//MessageBox(NULL, TEXT("Detach from process..."), NULL, NULL);
		if (trampoline_addr != NULL) {
			wprintf(TEXT("Rewriting back mov edi, edi\n"));
			memcpy(trampoline_addr, "\xCC\xCC\xCC\xCC\xCC\x8B\xFF", 7); // set back to mov edi, edi
		}
		if (old_protect != 0) {
			DWORD dontcare;
			if (!VirtualProtect(trampoline_addr, 7, old_protect, &dontcare)) {
				wprintf(TEXT("VirtualProtect failed"));
			}
			CloseHandle(next_file_addr);
		}
		//MessageBox(NULL, TEXT("Checkout with debugger"), NULL, NULL);
	}
	return TRUE;
}
