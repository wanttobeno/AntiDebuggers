#pragma once

#include <windows.h>

extern BOOL CALLBACK TestExceptionCode(DWORD dwCode);
extern BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam);