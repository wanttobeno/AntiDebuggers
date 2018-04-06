#include "stdafx.h"
#include <iostream>
#include <windows.h>

BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam)  
{  
	char cur_window[1024];
    GetWindowTextA(hwnd, cur_window, 1023);
	if (strstr(cur_window, "WinDbg")!=NULL || strstr(cur_window, "x64_dbg")!=NULL || strstr(cur_window, "OllyICE")!=NULL || strstr(cur_window, "OllyDBG")!=NULL || strstr(cur_window, "Immunity")!=NULL)
	{
		*((BOOL*)lParam) = TRUE;
	}
	return TRUE;
} 

BOOL CALLBACK TestExceptionCode(DWORD dwCode)
{
	__try
	{
		RaiseException(dwCode, 0, 0, 0);
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}