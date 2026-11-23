#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <fstream>
#include <sstream>
#include <memory>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define SYSBIN_APP_NAME   L"Sysbin System Tools"
#define SYSBIN_VERSION    L"1.0"
#define WM_SYSBIN_STATUS  (WM_APP + 1)

extern HINSTANCE g_hInst;
extern HWND      g_hMain;

// Common helpers (Common.cpp)
void         SetStatusText(const wchar_t* text);
void         LogMessage(HWND hList, const wchar_t* text);
std::wstring FormatBytes(ULONGLONG bytes);
std::wstring FormatNumber(ULONGLONG value);
bool         IsAdmin();
bool         EnablePrivilege(LPCWSTR privilege, bool enable);
std::wstring GetEnvPath(LPCWSTR name);
std::wstring GetExeDir();
std::wstring GetHostsPath();
std::wstring GetIniPath();
bool         FlushDnsCache();
bool         WaitForSingleProcess(LPCWSTR cmdline);
void         GetDlgUnitScale(HWND hDlg, double& ux, double& uy);
void         MoveDlgCtrlUnits(HWND hDlg, int id, int xDu, int yDu, int cxDu, int cyDu);

// Page dialog procedures
INT_PTR CALLBACK MemoryDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DiskDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK HostsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);
