#include "Sysbin.h"
#include "resource.h"

static const UINT_PTR MEM_REFRESH_TIMER = 1;

static void RefreshMemoryStatus(HWND hDlg)
{
    MEMORYSTATUSEX status;
    ZeroMemory(&status, sizeof(status));
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status))
        return;

    wchar_t buf[80] = { 0 };
    swprintf_s(buf, L"%llu MB / %.2f GB", status.ullTotalPhys / (1024ULL * 1024ULL),
        status.ullTotalPhys / (1024.0 * 1024.0 * 1024.0));
    SetDlgItemTextW(hDlg, IDC_MEM_TOTAL, buf);

    swprintf_s(buf, L"%llu MB", status.ullAvailPhys / (1024ULL * 1024ULL));
    SetDlgItemTextW(hDlg, IDC_MEM_AVAIL, buf);

    swprintf_s(buf, L"%lu %%", status.dwMemoryLoad);
    SetDlgItemTextW(hDlg, IDC_MEM_USAGE, buf);

    HWND hBar = GetDlgItem(hDlg, IDC_MEM_PROGRESS);
    SendMessageW(hBar, PBM_SETRANGE32, 0, 100);
    SendMessageW(hBar, PBM_SETPOS, status.dwMemoryLoad, 0);
}

static std::wstring ShortProcessName(DWORD pid)
{
    wchar_t name[MAX_PATH] = L"(unknown)";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h)
    {
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(h, 0, name, &len))
        {
            wchar_t* slash = wcsrchr(name, L'\\');
            if (slash)
                return std::wstring(slash + 1);
        }
        CloseHandle(h);
    }
    return name;
}

static ULONGLONG TrimAllWorkingSets(HWND hLog)
{
    std::vector<DWORD> ids(4096, 0);
    DWORD needed = 0;
    for (;;)
    {
        if (!EnumProcesses(&ids[0], (DWORD)(ids.size() * sizeof(DWORD)), &needed))
        {
            LogMessage(hLog, L"错误：无法枚举进程（EnumProcesses 失败）。");
            return 0;
        }
        DWORD count = needed / sizeof(DWORD);
        if (count < ids.size())
        {
            ids.resize(count);
            break;
        }
        ids.resize(ids.size() * 2);
    }

    DWORD self = GetCurrentProcessId();
    ULONGLONG totalFreed = 0;
    DWORD trimmed = 0, openDenied = 0, trimFailed = 0;

    bool debugPrivilege = EnablePrivilege(L"SeDebugPrivilege", true);
    LogMessage(hLog, debugPrivilege
        ? L"已启用 SeDebugPrivilege，正在整理各进程工作集..."
        : L"未能启用 SeDebugPrivilege，仍尝试整理当前用户的进程...");

    for (DWORD pid : ids)
    {
        if (pid == 0 || pid == self)
            continue;

        // EmptyWorkingSet requires PROCESS_SET_QUOTA in addition to VM_OPERATION.
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_SET_QUOTA, FALSE, pid);
        if (!hProc)
        {
            ++openDenied;
            continue;
        }

        PROCESS_MEMORY_COUNTERS before, after;
        ZeroMemory(&before, sizeof(before));
        ZeroMemory(&after, sizeof(after));
        bool hasBefore = GetProcessMemoryInfo(hProc, &before, sizeof(before)) != FALSE;

        if (EmptyWorkingSet(hProc) && hasBefore &&
            GetProcessMemoryInfo(hProc, &after, sizeof(after)))
        {
            if (before.WorkingSetSize > after.WorkingSetSize)
            {
                ULONGLONG freed = (ULONGLONG)before.WorkingSetSize - (ULONGLONG)after.WorkingSetSize;
                totalFreed += freed;
                ++trimmed;

                // Log every process that actually freed memory so the detail
                // lines add up exactly to the reported total.
                std::wstring name = ShortProcessName(pid);
                wchar_t line[512] = { 0 };
                swprintf_s(line, L"  PID %-6u  %-36s  释放 %s (%llu 字节)",
                    pid, name.c_str(), FormatBytes(freed).c_str(), freed);
                LogMessage(hLog, line);
            }
        }
        else
        {
            ++trimFailed;
        }
        CloseHandle(hProc);
    }

    wchar_t line[256] = { 0 };
    swprintf_s(line, L"进程工作集整理完成：成功压缩 %u 个进程；%u 个无法访问（受保护）；%u 个调用失败。",
        trimmed, openDenied, trimFailed);
    LogMessage(hLog, line);
    return totalFreed;
}

static void ReleaseMemory(HWND hDlg)
{
    HWND hLog = GetDlgItem(hDlg, IDC_MEM_LOG);
    LogMessage(hLog, L"========== 开始内存释放 ==========");

    ULONGLONG freed = TrimAllWorkingSets(hLog);

    bool cacheOk = false;
    if (EnablePrivilege(SE_INCREASE_QUOTA_NAME, true))
    {
        cacheOk = SetSystemFileCacheSize((SIZE_T)-1, (SIZE_T)-1, 0) != FALSE;
    }
    LogMessage(hLog, cacheOk
        ? L"系统文件缓存已清理（SetSystemFileCacheSize）。"
        : L"系统文件缓存清理被跳过（权限不足或系统拒绝）。");

    wchar_t line[256] = { 0 };
    swprintf_s(line, L"本次共回收工作集内存：%s (%llu 字节)",
        FormatBytes(freed).c_str(), freed);
    LogMessage(hLog, line);
    LogMessage(hLog, L"========== 内存释放完成 ==========");

    RefreshMemoryStatus(hDlg);

    swprintf_s(line, L"已回收 %s 内存", FormatBytes(freed).c_str());
    SetStatusText(line);
}

INT_PTR CALLBACK MemoryDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        RefreshMemoryStatus(hDlg);
        SetTimer(hDlg, MEM_REFRESH_TIMER, 2000, nullptr);
        return TRUE;

    case WM_TIMER:
        if (wParam == MEM_REFRESH_TIMER)
            RefreshMemoryStatus(hDlg);
        return TRUE;

    case WM_SIZE:
    {
        double ux, uy;
        GetDlgUnitScale(hDlg, ux, uy);
        int wDu = (int)(LOWORD(lParam) / ux);
        int hDu = (int)(HIWORD(lParam) / uy);
        if (wDu < 400 || hDu < 250)
            return TRUE;
        MoveDlgCtrlUnits(hDlg, IDC_MEM_GROUP, 8, 6, wDu - 16, 112);
        MoveDlgCtrlUnits(hDlg, IDC_MEM_AVAIL, wDu - 164, 28, 140, 14);
        MoveDlgCtrlUnits(hDlg, IDC_MEM_HINT, wDu - 232, 52, 210, 28);
        MoveDlgCtrlUnits(hDlg, IDC_MEM_PROGRESS, 22, 86, wDu - 44, 18);
        MoveDlgCtrlUnits(hDlg, IDC_MEM_HINT2, wDu - 142, 128, 134, 22);
        MoveDlgCtrlUnits(hDlg, IDC_MEM_LOG, 8, 158, wDu - 16, hDu - 166);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_MEM_REFRESH:
            RefreshMemoryStatus(hDlg);
            SetStatusText(L"内存状态已刷新");
            return TRUE;

        case IDC_MEM_RELEASE:
            ReleaseMemory(hDlg);
            return TRUE;

        case IDC_MEM_CLEARLOG:
            SendDlgItemMessageW(hDlg, IDC_MEM_LOG, LB_RESETCONTENT, 0, 0);
            return TRUE;
        }
        break;

    case WM_DESTROY:
        KillTimer(hDlg, MEM_REFRESH_TIMER);
        return TRUE;
    }
    return FALSE;
}
