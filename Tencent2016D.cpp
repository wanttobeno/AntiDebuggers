// Tencent2016D.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <iostream>
#include <windows.h>
#include <Tlhelp32.h>
#include <process.h>
#include "Tencent2016D.h"
#include "Tencent2016DAPI.h"
#include "Tencent2016Globle.h"

using namespace std;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

BOOL CheckDebug1()
{
	return IsDebuggerPresent();
}

BOOL CheckDebug2()
{
	BOOL ret;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret);
	return ret;
}

BOOL CheckDebug3()
{
	int debugPort = 0;
	HMODULE hModule = LoadLibrary("Ntdll.dll");
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hModule, "NtQueryInformationProcess");
	if (NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL))
	{
		MessageBox(NULL, "[ERROR NtQueryInformationProcessApproach] NtQueryInformationProcess failed", "error", MB_OK);
		return FALSE;
	}
	else
	{
		return debugPort != 0;
	}
}

BOOL CheckDebug4()
{
	DWORD errorValue = 12345;
	SetLastError(errorValue);
	OutputDebugString("Test for debugger!");
	if (GetLastError() == errorValue)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug5()
{
	char fib[1024] = { 0 };
	DeleteFiber(fib);
	return (GetLastError() != 0x57);
}

BOOL CheckDebug6()
{
	DWORD ret = CloseHandle((HANDLE)0x1234);
	if (ret != 0 || GetLastError() != ERROR_INVALID_HANDLE)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug7()
{
	DWORD ret = CloseWindow((HWND)0x1234);
	if (ret != 0 || GetLastError() != ERROR_INVALID_WINDOW_HANDLE)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug8()
{
	char result = 0;
	__asm
	{
		mov eax, fs:[30h]
		mov al, BYTE PTR[eax + 2]
		mov result, al
	}
	return result != 0;
}

BOOL CheckDebug9()
{
	int result = 0;
	DWORD dwVersion = GetVersion();
	DWORD dwWindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwWindowsMajorVersion == 5)
	{
		__asm
		{
			mov eax, fs:[30h]
			mov eax, [eax + 18h]
			mov eax, [eax + 10h]
			mov result, eax
		}
	}
	else
	{
		__asm
		{
			mov eax, fs:[30h]
			mov eax, [eax + 18h]
			mov eax, [eax + 44h]
			mov result, eax
		}
	}
	return result != 0;
}

BOOL CheckDebug10()
{
	int result = 0;
	DWORD dwVersion = GetVersion();
	DWORD dwWindowsMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if (dwWindowsMajorVersion == 5)
	{
		__asm
		{
			mov eax, fs:[30h]
			mov eax, [eax + 18h]
			mov eax, [eax + 0ch]
			mov result, eax
		}
	}
	else
	{
		__asm
		{
			mov eax, fs:[30h]
			mov eax, [eax + 18h]
			mov eax, [eax + 40h]
			mov result, eax
		}
	}
	return result != 2;
}

BOOL CheckDebug11()
{
	int result = 0;
	__asm
	{
		mov eax, fs:[30h]
		mov eax, [eax + 68h]
		and eax, 0x70
		mov result, eax
	}
	return result != 0;
}

BOOL CheckDebug12()
{
	BOOL is_64;
	HKEY hkey = NULL;
	char key[] = "Debugger";
	IsWow64Process(GetCurrentProcess(), &is_64);
	char reg_dir_32bit[] = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug";
	char reg_dir_64bit[] = "SOFTWARE\\Wow6432Node\\Microsoft\\WindowsNT\\CurrentVersion\\AeDebug";
	DWORD ret = 0;
	if (is_64)
	{
		ret = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_dir_64bit, &hkey);
	}
	else
	{
		ret = RegCreateKeyA(HKEY_LOCAL_MACHINE, reg_dir_32bit, &hkey);
	}
	if (ret != ERROR_SUCCESS)
	{
		return FALSE;
	}
	DWORD type;
	char tmp[256];
	DWORD len = 256;
	ret = RegQueryValueExA(hkey, key, NULL, &type, (LPBYTE)tmp, &len);
	if (strstr(tmp, "OllyIce") != NULL || strstr(tmp, "OllyDBG") != NULL || strstr(tmp, "WinDbg") != NULL || strstr(tmp, "x64dbg") != NULL || strstr(tmp, "Immunity") != NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug13()
{
	if (FindWindowA("OLLYDBG", NULL) != NULL || FindWindowA("WinDbgFrameClass", NULL) != NULL || FindWindowA("QWidget", NULL) != NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug14()
{
	BOOL ret = FALSE;
	EnumWindows(EnumWndProc, (LPARAM)&ret);
	return ret;
}

BOOL CheckDebug15()
{
	char fore_window[1024];
	GetWindowTextA(GetForegroundWindow(), fore_window, 1023);
	if (strstr(fore_window, "WinDbg") != NULL || strstr(fore_window, "x64_dbg") != NULL || strstr(fore_window, "OllyICE") != NULL || strstr(fore_window, "OllyDBG") != NULL || strstr(fore_window, "Immunity") != NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug16()
{
	DWORD ID;
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (stricmp(pe32.szExeFile, "OllyDBG.EXE") == 0 || stricmp(pe32.szExeFile, "OllyICE.exe") == 0 || stricmp(pe32.szExeFile, "x64_dbg.exe") == 0 || stricmp(pe32.szExeFile, "windbg.exe") == 0 || stricmp(pe32.szExeFile, "ImmunityDebugger.exe") == 0)
		{
			return TRUE;
		}
		bMore = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FALSE;
}

BOOL CheckDebug17()
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwBaseImage = (DWORD)GetModuleHandle(NULL); 
	pDosHeader = (PIMAGE_DOS_HEADER)dwBaseImage;
	pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(pNtHeaders->Signature) + sizeof(IMAGE_FILE_HEADER) +
		(WORD)pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD dwAddr = pSectionHeader->VirtualAddress + dwBaseImage; 
	DWORD dwCodeSize = pSectionHeader->SizeOfRawData;   
	BOOL Found = FALSE;
	__asm
	{
		cld
		mov     edi, dwAddr
		mov     ecx, dwCodeSize
		mov     al, 0CCH
		repne   scasb
		jnz     NotFound
		mov Found, 1
		NotFound:
	}
	return Found;
}

BOOL CheckDebug18()
{
	CONTEXT context;
	HANDLE hThread = GetCurrentThread();
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hThread, &context);
	if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
	{
		return TRUE;
	}
	return FALSE;
}

BOOL CheckDebug19()
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD dwBaseImage = (DWORD)GetModuleHandle(NULL); 
	pDosHeader = (PIMAGE_DOS_HEADER)dwBaseImage;
	pNtHeaders = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(pNtHeaders->Signature) + sizeof(IMAGE_FILE_HEADER) +
		(WORD)pNtHeaders->FileHeader.SizeOfOptionalHeader);
	DWORD dwAddr = pSectionHeader->VirtualAddress + dwBaseImage; 
	DWORD dwCodeSize = pSectionHeader->SizeOfRawData;    
	DWORD checksum = 0;
	__asm
	{
		cld
		mov     esi, dwAddr
		mov     ecx, dwCodeSize
		xor eax, eax
	checksum_loop :
		movzx    ebx, byte ptr[esi]
		add        eax, ebx
		rol eax, 1
		inc esi
		loop       checksum_loop
		mov checksum, eax
	}
	if (checksum != 0x46ea24)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL CheckDebug20()
{
	DWORD time1, time2;
	__asm
	{
		rdtsc
		mov time1, eax
		rdtsc
		mov time2, eax
	}
	if (time2 - time1 < 0xff)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL CheckDebug21()
{
	DWORD time1 = GetTickCount();
	__asm
	{
		mov     ecx, 10
		mov     edx, 6
		mov     ecx, 10
	}
	DWORD time2 = GetTickCount();
	if (time2 - time1 > 0x1A)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug22()
{
	LONG                      status;
	DWORD                     dwParentPID = 0;
	HANDLE                    hProcess;
	PROCESS_BASIC_INFORMATION pbi;
	int pid = getpid();
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (!hProcess)
	{
		return -1;
	}
	PNTQUERYINFORMATIONPROCESS  NtQueryInformationProcess = (PNTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
	status = NtQueryInformationProcess(hProcess, SystemBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (pbi.InheritedFromUniqueProcessId == pe32.th32ProcessID)
		{
			if (stricmp(pe32.szExeFile, "explorer.exe") == 0)
			{
				CloseHandle(hProcessSnap);
				return FALSE;
			}
			else
			{
				CloseHandle(hProcessSnap);
				return TRUE;
			}
		}
		bMore = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
}

BOOL CheckDebug23()
{
	STARTUPINFO si;
	GetStartupInfo(&si);
	if (si.dwX != 0 || si.dwY != 0 || si.dwFillAttribute != 0 || si.dwXSize != 0 || si.dwYSize != 0 || si.dwXCountChars != 0 || si.dwYCountChars != 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug24()
{
	DWORD ID;
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32);
	while (bMore)
	{
		if (strcmp(pe32.szExeFile, "csrss.exe") == 0)
		{
			ID = pe32.th32ProcessID;
			break;
		}
		bMore = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	if (OpenProcess(PROCESS_QUERY_INFORMATION, NULL, ID) != NULL)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckDebug25()
{
	__try
	{
		__asm int 3
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDebug26()
{
	__try
	{
		__asm
		{
			__emit 0xCD
			__emit 0x03
		}
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDebug27()
{
	__try
	{
		__asm int 0x2d
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDebug28()
{
	__try
	{
		__asm __emit 0xF1
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDebug29()
{
	__try
	{
		__asm
		{
			pushfd
			or word ptr[esp], 0x100
			popfd
			nop
		}
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CheckDebug30()
{
	return TestExceptionCode(DBG_RIPEXCEPTION);
}