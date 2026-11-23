#include "Sysbin.h"

void SetStatusText(const wchar_t* text)
{
    if (g_hMain && IsWindow(g_hMain))
        SendMessageW(g_hMain, WM_SYSBIN_STATUS, 0, (LPARAM)text);
}

void LogMessage(HWND hList, const wchar_t* text)
{
    if (!hList || !IsWindow(hList) || !text)
        return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t line[1024];
    swprintf_s(line, L"[%02d:%02d:%02d] %s", st.wHour, st.wMinute, st.wSecond, text);

    int index = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)line);
    if (index >= 0)
    {
        SendMessageW(hList, LB_SETTOPINDEX, index, 0);
        SendMessageW(hList, LB_SETSEL, TRUE, index);
    }
}

std::wstring FormatBytes(ULONGLONG bytes)
{
    wchar_t buf[64] = { 0 };
    if (bytes < 1024ULL)
        swprintf_s(buf, L"%llu B", bytes);
    else if (bytes < 1024ULL * 1024ULL)
        swprintf_s(buf, L"%.1f KB", bytes / 1024.0);
    else if (bytes < 1024ULL * 1024ULL * 1024ULL)
        swprintf_s(buf, L"%.1f MB", bytes / (1024.0 * 1024.0));
    else
        swprintf_s(buf, L"%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

std::wstring FormatNumber(ULONGLONG value)
{
    wchar_t buf[64] = { 0 };
    swprintf_s(buf, L"%llu", value);
    return buf;
}

bool IsAdmin()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (AllocateAndInitializeSid(&authority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &administrators))
    {
        CheckTokenMembership(nullptr, administrators, &isAdmin);
        FreeSid(administrators);
    }
    return isAdmin != FALSE;
}

bool EnablePrivilege(LPCWSTR privilege, bool enable)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp;
    ZeroMemory(&tp, sizeof(tp));
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, privilege, &tp.Privileges[0].Luid))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
        BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        ok = adjusted && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

std::wstring GetEnvPath(LPCWSTR name)
{
    DWORD len = GetEnvironmentVariableW(name, nullptr, 0);
    if (len == 0)
        return std::wstring();
    std::wstring value(len, L'\0');
    GetEnvironmentVariableW(name, &value[0], len);
    if (!value.empty() && value.back() == L'\0')
        value.pop_back();
    return value;
}

std::wstring GetExeDir()
{
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(g_hInst ? g_hInst : GetModuleHandle(nullptr), path, MAX_PATH);
    std::wstring full(path);
    size_t slash = full.find_last_of(L"\\/");
    return slash == std::wstring::npos ? full : full.substr(0, slash);
}

std::wstring GetHostsPath()
{
    wchar_t dir[MAX_PATH] = { 0 };
    GetSystemDirectoryW(dir, MAX_PATH);
    std::wstring path(dir);
    path += L"\\drivers\\etc\\hosts";
    return path;
}

std::wstring GetIniPath()
{
    return GetExeDir() + L"\\SysbinHosts.ini";
}

bool WaitForSingleProcess(LPCWSTR cmdline)
{
    std::wstring mutableCmd(cmdline ? cmdline : L"");
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessW(nullptr, &mutableCmd[0], nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!created)
        return false;

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return code == 0;
}

bool FlushDnsCache()
{
    return WaitForSingleProcess(L"ipconfig.exe /flushdns");
}

void GetDlgUnitScale(HWND hDlg, double& ux, double& uy)
{
    RECT probe = { 0, 0, 100, 100 };
    MapDialogRect(hDlg, &probe);
    ux = probe.right / 100.0;
    uy = probe.bottom / 100.0;
    if (ux <= 0) ux = 1.0;
    if (uy <= 0) uy = 1.0;
}

void MoveDlgCtrlUnits(HWND hDlg, int id, int xDu, int yDu, int cxDu, int cyDu)
{
    HWND ctrl = GetDlgItem(hDlg, id);
    if (!ctrl)
        return;
    RECT r = { xDu, yDu, xDu + cxDu, yDu + cyDu };
    MapDialogRect(hDlg, &r);
    MoveWindow(ctrl, r.left, r.top, r.right - r.left, r.bottom - r.top, TRUE);
}
