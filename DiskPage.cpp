#include "Sysbin.h"
#include "resource.h"
#include <winsvc.h>

#define TARGET_TEMP      0x0001
#define TARGET_WINTEMP   0x0002
#define TARGET_RECYCLE   0x0004
#define TARGET_PREFETCH  0x0008
#define TARGET_THUMBS    0x0010
#define TARGET_BROWSER   0x0020
#define TARGET_UPDATE    0x0040

struct ScanResult
{
    ULONGLONG bytes = 0;
    DWORD files = 0;

    void Add(const ScanResult& other)
    {
        bytes += other.bytes;
        files += other.files;
    }
};

static ULONGLONG FileSizeOf(const WIN32_FIND_DATAW& fd)
{
    return ((ULONGLONG)fd.nFileSizeHigh << 32) | (ULONGLONG)fd.nFileSizeLow;
}

static bool IsDots(const wchar_t* name)
{
    return wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0;
}

static void ScanDirContents(const std::wstring& dir, ScanResult& result, int depth = 0)
{
    if (depth > 32 || dir.empty())
        return;

    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (IsDots(fd.cFileName))
            continue;

        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;
            ScanDirContents(full, result, depth + 1);
        }
        else
        {
            result.bytes += FileSizeOf(fd);
            ++result.files;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void CleanDirContents(const std::wstring& dir, ScanResult& result, int depth = 0)
{
    if (depth > 32 || dir.empty())
        return;

    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (IsDots(fd.cFileName))
            continue;

        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;
            CleanDirContents(full, result, depth + 1);
            RemoveDirectoryW(full.c_str());
        }
        else
        {
            ULONGLONG size = FileSizeOf(fd);
            if (DeleteFileW(full.c_str()))
            {
                result.bytes += size;
                ++result.files;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void HandlePattern(const std::wstring& dir, const std::wstring& pattern,
                          ScanResult& result, bool clean)
{
    if (dir.empty())
        return;
    std::wstring fullPattern = dir + L"\\" + pattern;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(fullPattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (IsDots(fd.cFileName) || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        ULONGLONG size = FileSizeOf(fd);
        if (!clean)
        {
            result.bytes += size;
            ++result.files;
        }
        else
        {
            std::wstring full = dir + L"\\" + fd.cFileName;
            if (DeleteFileW(full.c_str()))
            {
                result.bytes += size;
                ++result.files;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void HandleBrowserRoot(const std::wstring& userData, ScanResult& result, bool clean)
{
    if (userData.empty())
        return;
    std::wstring pattern = userData + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (IsDots(fd.cFileName) || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        std::wstring name = fd.cFileName;
        bool isProfile = (name == L"Default") ||
                         (name.size() >= 7 && name.substr(0, 7) == L"Profile");
        if (!isProfile)
            continue;

        std::wstring profileDir = userData + L"\\" + name;
        const wchar_t* cacheDirs[] = { L"Cache", L"Code Cache" };
        for (const wchar_t* cache : cacheDirs)
        {
            std::wstring target = profileDir + L"\\" + cache;
            if (clean)
                CleanDirContents(target, result);
            else
                ScanDirContents(target, result);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void HandleFirefox(ScanResult& result, bool clean)
{
    std::wstring local = GetEnvPath(L"LOCALAPPDATA");
    if (local.empty())
        return;
    std::wstring profilesRoot = local + L"\\Mozilla\\Firefox\\Profiles";
    std::wstring pattern = profilesRoot + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (IsDots(fd.cFileName) || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        std::wstring cache = profilesRoot + L"\\" + fd.cFileName + L"\\cache2";
        if (clean)
            CleanDirContents(cache, result);
        else
            ScanDirContents(cache, result);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static void HandleRecycleBin(ScanResult& result, bool clean)
{
    if (clean)
    {
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        if (SUCCEEDED(hr))
            result.files = 1; // approximate: recycle bin is emptied as a whole
        return;
    }

    SHQUERYRBINFO info;
    ZeroMemory(&info, sizeof(info));
    info.cbSize = sizeof(info);
    if (SUCCEEDED(SHQueryRecycleBinW(nullptr, &info)))
    {
        result.bytes = (ULONGLONG)info.i64Size;
        result.files = (DWORD)info.i64NumItems;
    }
}

static DWORD GetSelectedTargets(HWND hDlg)
{
    DWORD mask = 0;
    if (IsDlgButtonChecked(hDlg, IDC_CK_TEMP) == BST_CHECKED)     mask |= TARGET_TEMP;
    if (IsDlgButtonChecked(hDlg, IDC_CK_WINTEMP) == BST_CHECKED)  mask |= TARGET_WINTEMP;
    if (IsDlgButtonChecked(hDlg, IDC_CK_RECYCLE) == BST_CHECKED)  mask |= TARGET_RECYCLE;
    if (IsDlgButtonChecked(hDlg, IDC_CK_PREFETCH) == BST_CHECKED) mask |= TARGET_PREFETCH;
    if (IsDlgButtonChecked(hDlg, IDC_CK_THUMBS) == BST_CHECKED)   mask |= TARGET_THUMBS;
    if (IsDlgButtonChecked(hDlg, IDC_CK_BROWSER) == BST_CHECKED)  mask |= TARGET_BROWSER;
    if (IsDlgButtonChecked(hDlg, IDC_CK_UPDATE) == BST_CHECKED)   mask |= TARGET_UPDATE;
    return mask;
}

static void ProcessTargets(HWND hDlg, DWORD mask, bool clean)
{
    HWND hLog = GetDlgItem(hDlg, IDC_DISK_LOG);
    ScanResult total;
    std::wstring windir = GetEnvPath(L"WINDIR");
    std::wstring local = GetEnvPath(L"LOCALAPPDATA");
    wchar_t tempBuf[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempBuf);
    std::wstring userTemp(tempBuf);
    while (!userTemp.empty() && (userTemp.back() == L'\\' || userTemp.back() == L'/'))
        userTemp.pop_back();

    auto run = [&](DWORD flag, const wchar_t* label, std::function<void(ScanResult&, bool)> fn)
    {
        if (!(mask & flag))
            return;
        ScanResult one;
        fn(one, clean);
        total.Add(one);
        wchar_t line[256] = { 0 };
        if (clean)
            swprintf_s(line, L"%s：已清理 %s（%u 项）", label,
                FormatBytes(one.bytes).c_str(), one.files);
        else
            swprintf_s(line, L"%s：可释放 %s（%u 个文件）", label,
                FormatBytes(one.bytes).c_str(), one.files);
        LogMessage(hLog, line);
    };

    LogMessage(hLog, clean ? L"========== 开始清理 ==========" : L"========== 开始扫描 ==========");

    run(TARGET_TEMP, L"用户临时文件", [&](ScanResult& r, bool c) {
        if (c) CleanDirContents(userTemp, r); else ScanDirContents(userTemp, r);
    });

    run(TARGET_WINTEMP, L"系统临时文件", [&](ScanResult& r, bool c) {
        std::wstring dir = windir + L"\\Temp";
        if (c) CleanDirContents(dir, r); else ScanDirContents(dir, r);
    });

    run(TARGET_RECYCLE, L"回收站", [](ScanResult& r, bool c) { HandleRecycleBin(r, c); });

    run(TARGET_PREFETCH, L"Prefetch 预读缓存", [&](ScanResult& r, bool c) {
        HandlePattern(windir + L"\\Prefetch", L"*.pf", r, c);
    });

    run(TARGET_THUMBS, L"缩略图缓存", [&](ScanResult& r, bool c) {
        if (!local.empty())
            HandlePattern(local + L"\\Microsoft\\Windows\\Explorer", L"thumbcache_*.db", r, c);
    });

    run(TARGET_BROWSER, L"浏览器缓存", [&](ScanResult& r, bool c) {
        if (local.empty()) return;
        HandleBrowserRoot(local + L"\\Google\\Chrome\\User Data", r, c);
        HandleBrowserRoot(local + L"\\Microsoft\\Edge\\User Data", r, c);
        HandleFirefox(r, c);
    });

    run(TARGET_UPDATE, L"Windows 更新缓存", [&](ScanResult& r, bool c) {
        std::wstring dir = windir + L"\\SoftwareDistribution\\Download";
        if (c)
        {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            SC_HANDLE svc = scm ? OpenServiceW(scm, L"wuauserv",
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP) : nullptr;
            SERVICE_STATUS ss;
            ZeroMemory(&ss, sizeof(ss));
            bool wasRunning = false;
            if (svc && QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING)
            {
                wasRunning = true;
                ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                for (int i = 0; i < 20 && ss.dwCurrentState != SERVICE_STOPPED; ++i)
                {
                    Sleep(250);
                    if (!QueryServiceStatus(svc, &ss)) break;
                }
            }
            CleanDirContents(dir, r);
            if (wasRunning && svc)
                StartServiceW(svc, 0, nullptr);
            if (svc) CloseServiceHandle(svc);
            if (scm) CloseServiceHandle(scm);
        }
        else
        {
            ScanDirContents(dir, r);
        }
    });

    wchar_t summary[256] = { 0 };
    if (mask == 0)
    {
        LogMessage(hLog, L"未选择任何清理项目。");
        wcscpy_s(summary, L"扫描结果：请先勾选清理项目");
    }
    else if (clean)
    {
        swprintf_s(summary, L"扫描结果：本次已释放 %s（%u 项）",
            FormatBytes(total.bytes).c_str(), total.files);
        LogMessage(hLog, summary);
        LogMessage(hLog, L"========== 清理完成 ==========");
    }
    else
    {
        swprintf_s(summary, L"扫描结果：可释放 %s（%u 个文件）",
            FormatBytes(total.bytes).c_str(), total.files);
        LogMessage(hLog, summary);
        LogMessage(hLog, L"========== 扫描完成，点击“开始清理”执行 ==========");
    }
    SetDlgItemTextW(hDlg, IDC_DISK_SUMMARY, summary);
    SetStatusText(summary);
}

INT_PTR CALLBACK DiskDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        CheckDlgButton(hDlg, IDC_CK_TEMP, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_WINTEMP, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_RECYCLE, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_BROWSER, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_PREFETCH, BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CK_THUMBS, BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CK_UPDATE, BST_UNCHECKED);
        return TRUE;

    case WM_SIZE:
    {
        double ux, uy;
        GetDlgUnitScale(hDlg, ux, uy);
        int wDu = (int)(LOWORD(lParam) / ux);
        int hDu = (int)(HIWORD(lParam) / uy);
        if (wDu < 400 || hDu < 250)
            return TRUE;
        int rightX = wDu - 252;
        UINT rightIds[] = { IDC_CK_WINTEMP, IDC_CK_PREFETCH, IDC_CK_BROWSER, IDC_DISK_SUMMARY };
        int rightY[] = { 12, 36, 60, 84 };
        for (int i = 0; i < 4; ++i)
            MoveDlgCtrlUnits(hDlg, rightIds[i], rightX, rightY[i], 236, 18);
        MoveDlgCtrlUnits(hDlg, IDC_DISK_CLEARLOG, wDu - 118, 112, 110, 26);
        MoveDlgCtrlUnits(hDlg, IDC_DISK_LOG, 8, 148, wDu - 16, hDu - 156);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_DISK_SCAN:
            ProcessTargets(hDlg, GetSelectedTargets(hDlg), false);
            return TRUE;

        case IDC_DISK_CLEAN:
            if (GetSelectedTargets(hDlg) == 0)
            {
                MessageBoxW(hDlg, L"请至少勾选一个清理项目。", L"Sysbin System Tools", MB_ICONINFORMATION);
                return TRUE;
            }
            ProcessTargets(hDlg, GetSelectedTargets(hDlg), true);
            return TRUE;

        case IDC_DISK_SELECTALL:
        case IDC_DISK_SELECTNONE:
        {
            bool select = LOWORD(wParam) == IDC_DISK_SELECTALL;
            UINT ids[] = { IDC_CK_TEMP, IDC_CK_WINTEMP, IDC_CK_RECYCLE, IDC_CK_PREFETCH,
                           IDC_CK_THUMBS, IDC_CK_BROWSER, IDC_CK_UPDATE };
            for (UINT id : ids)
                CheckDlgButton(hDlg, id, select ? BST_CHECKED : BST_UNCHECKED);
            return TRUE;
        }

        case IDC_DISK_CLEARLOG:
            SendDlgItemMessageW(hDlg, IDC_DISK_LOG, LB_RESETCONTENT, 0, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}
