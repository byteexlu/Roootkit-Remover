#include <windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <iostream>
#include <stdio.h>
#include <tlhelp32.h>
#include <taskschd.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Taskschd.lib")

#define IS_64_BITS (sizeof(void*) == 8)

BOOL IsRunAsAdmin()
{
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
	{
		CheckTokenMembership(NULL, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}
	return isAdmin;
}

void RelaunchAsAdmin()
{
	if (!IsRunAsAdmin())
	{
		wchar_t szPath[MAX_PATH];
		GetModuleFileNameW(NULL, szPath, MAX_PATH);

		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.lpVerb = L"runas";
		sei.lpFile = szPath;
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;

		if (ShellExecuteExW(&sei))
		{
			ExitProcess(0);
		}
	}
}

BOOL IsOs64Bit()
{
	BOOL isWow64 = FALSE;
	return IS_64_BITS || (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64);
}

VOID UnhookModule(HANDLE hProc, LPCWSTR dllName)
{
	if (!hProc || !dllName) return;

	WCHAR sysPath[MAX_PATH] = { 0 };
	WCHAR winDir[MAX_PATH] = { 0 };
	GetWindowsDirectoryW(winDir, MAX_PATH);

	swprintf_s(sysPath, MAX_PATH, L"%c:\\Windows\\%s\\%s",
		winDir[0],
		(IsOs64Bit() && !IS_64_BITS) ? L"SysWOW64" : L"System32",
		dllName);

	HMODULE hMod = GetModuleHandleW(dllName);
	if (!hMod) return;

	MODULEINFO modInfo = { 0 };
	if (!GetModuleInformation(hProc, hMod, &modInfo, sizeof(MODULEINFO))) return;

	HANDLE hFile = CreateFileW(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return;

	HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMap)
	{
		LPVOID pMapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
		if (pMapped)
		{
			PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)modInfo.lpBaseOfDll + ((PIMAGE_DOS_HEADER)modInfo.lpBaseOfDll)->e_lfanew);
			PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

			for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++)
			{
				if (strcmp((char*)pSec->Name, ".text") == 0)
				{
					LPVOID pTarget = (LPVOID)((ULONG_PTR)modInfo.lpBaseOfDll + pSec->VirtualAddress);
					DWORD size = pSec->Misc.VirtualSize;
					DWORD oldProtect = 0;

					if (VirtualProtectEx(hProc, pTarget, size, PAGE_EXECUTE_READWRITE, &oldProtect))
					{
						WriteProcessMemory(hProc, pTarget, (LPVOID)((ULONG_PTR)pMapped + pSec->VirtualAddress), size, NULL);
						VirtualProtectEx(hProc, pTarget, size, oldProtect, &oldProtect);
					}
					break;
				}
			}
			UnmapViewOfFile(pMapped);
		}
		CloseHandle(hMap);
	}
	CloseHandle(hFile);
	FreeLibrary(hMod);
}

BOOL SetDebugPrivilege()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL status = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	DWORD err = GetLastError();

	CloseHandle(hToken);
	return status && (err != ERROR_NOT_ALL_ASSIGNED);
}

BOOL RemoveTask(LPCWSTR taskName)
{
	BOOL ok = FALSE;
	BSTR bName = SysAllocString(taskName);
	BSTR bRoot = SysAllocString(L"\\");

	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
	{
		SysFreeString(bName);
		SysFreeString(bRoot);
		return FALSE;
	}

	CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);

	ITaskService* pService = NULL;
	if (SUCCEEDED(CoCreateInstance(__uuidof(TaskScheduler), nullptr, CLSCTX_INPROC_SERVER, __uuidof(ITaskService), (void**)&pService)))
	{
		VARIANT empty;
		VariantInit(&empty);

		if (SUCCEEDED(pService->Connect(empty, empty, empty, empty)))
		{
			ITaskFolder* pFolder = NULL;
			if (SUCCEEDED(pService->GetFolder(bRoot, &pFolder)))
			{
				if (SUCCEEDED(pFolder->DeleteTask(bName, 0)))
				{
					ok = TRUE;
				}
				pFolder->Release();
			}
		}
		pService->Release();
	}

	CoUninitialize();
	SysFreeString(bName);
	SysFreeString(bRoot);
	return ok;
}

void SetRedColor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
}

void ResetColor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void ShowHeader()
{
	SetRedColor();
	std::cout << "By Mikey\n";
	std::cout << "GitHub: https://github.com/byteexlu\n\n";
	ResetColor();
}

void ExecuteRemoval()
{
	std::cout << "Wait...\n";

	LPCWSTR targetDlls[] = {
		L"ntdll.dll",
		L"advapi32.dll",
		L"sechost.dll",
		L"pdh.dll",
		L"amsi.dll"
	};
	DWORD dllCount = sizeof(targetDlls) / sizeof(targetDlls[0]);

	Sleep(1000);

	HANDLE hCurrent = GetCurrentProcess();
	for (DWORD i = 0; i < dllCount; i++)
	{
		UnhookModule(hCurrent, targetDlls[i]);
	}

	SetDebugPrivilege();

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W pe = { 0 };
		pe.dwSize = sizeof(pe);

		if (Process32FirstW(hSnap, &pe))
		{
			do
			{
				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
				if (!hProc) continue;

				if (_wcsicmp(pe.szExeFile, L"dllhost.exe") == 0)
				{
					TerminateProcess(hProc, 0);
				}
				else
				{
					for (DWORD i = 0; i < dllCount; i++)
					{
						UnhookModule(hProc, targetDlls[i]);
					}
				}
				CloseHandle(hProc);
			} while (Process32NextW(hSnap, &pe));
		}
		CloseHandle(hSnap);
	}

	RemoveTask(L"$77svc64");
	RemoveTask(L"$77svc32");

	std::cout << "Done.\n";
}

int main()
{
	RelaunchAsAdmin();

	while (true)
	{
		system("cls");
		ShowHeader();

		std::cout << "[1] Remove Rootkit\n";
		std::cout << "[0] Exit\n\n";
		std::cout << "Select an option: ";

		int choice = -1;
		std::cin >> choice;

		if (choice == 1)
		{
			ExecuteRemoval();

			std::cout << "\nPress Enter to return to the main menu...";
			std::cin.ignore();
			std::cin.get();
		}
		else if (choice == 0)
		{
			std::cout << "Exiting...\n";
			ResetColor();
			return 0;
		}
	}

	ResetColor();
	return 0;
}