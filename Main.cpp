#include "Sysbin.h"
#include "resource.h"

HINSTANCE g_hInst = nullptr;
HWND      g_hMain = nullptr;

static HWND g_hTab = nullptr;
static HWND g_hPages[3] = { nullptr, nullptr, nullptr };
static const wchar_t* g_tabNames[3] = { L"内存释放", L"硬盘清理", L"Hosts 加速" };

static void LayoutTabPages()
{
    if (!g_hTab || !IsWindow(g_hTab))
        return;

    RECT rc;
    GetClientRect(g_hTab, &rc);
    TabCtrl_AdjustRect(g_hTab, FALSE, &rc);

    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    for (int i = 0; i < 3; ++i)
    {
        if (g_hPages[i])
            MoveWindow(g_hPages[i], rc.left, rc.top, width, height, TRUE);
    }
}

static void CenterWindow(HWND hwnd)
{
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(hwnd, nullptr,
        (w - (rc.right - rc.left)) / 2,
        (h - (rc.bottom - rc.top)) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

static void OnMainSize(HWND hDlg)
{
    RECT rc;
    GetClientRect(hDlg, &rc);
    int statusHeight = 30;
    int tabHeight = rc.bottom - statusHeight;
    if (tabHeight < 0) tabHeight = 0;

    if (g_hTab)
        MoveWindow(g_hTab, 0, 0, rc.right, tabHeight, TRUE);
    HWND hStatus = GetDlgItem(hDlg, IDC_STATUS);
    if (hStatus)
        MoveWindow(hStatus, 0, tabHeight, rc.right, statusHeight, TRUE);

    LayoutTabPages();
}

static BOOL OnInitDialog(HWND hDlg)
{
    g_hMain = hDlg;

    HICON hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCE(IDI_SYSBIN),
        IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    if (hIcon)
    {
        SendMessageW(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        HICON hSmall = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCE(IDI_SYSBIN),
            IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        if (hSmall)
            SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hSmall);
    }

    g_hTab = GetDlgItem(hDlg, IDC_TAB);
    TCITEMW item;
    ZeroMemory(&item, sizeof(item));
    item.mask = TCIF_TEXT;
    for (int i = 0; i < 3; ++i)
    {
        item.pszText = (LPWSTR)g_tabNames[i];
        TabCtrl_InsertItem(g_hTab, i, &item);
    }

    g_hPages[0] = CreateDialogParamW(g_hInst, MAKEINTRESOURCE(IDD_PAGE_MEM),
        g_hTab, MemoryDlgProc, 0);
    g_hPages[1] = CreateDialogParamW(g_hInst, MAKEINTRESOURCE(IDD_PAGE_DISK),
        g_hTab, DiskDlgProc, 0);
    g_hPages[2] = CreateDialogParamW(g_hInst, MAKEINTRESOURCE(IDD_PAGE_HOSTS),
        g_hTab, HostsDlgProc, 0);

    OnMainSize(hDlg);
    ShowWindow(g_hPages[0], SW_SHOW);
    ShowWindow(g_hPages[1], SW_HIDE);
    ShowWindow(g_hPages[2], SW_HIDE);

    std::wstring status = IsAdmin()
        ? std::wstring(L"就绪  |  已获得管理员权限  |  版本 ") + SYSBIN_VERSION
        : std::wstring(L"警告：未以管理员身份运行，部分功能可能受限  |  版本 ") + SYSBIN_VERSION;
    SetStatusText(status.c_str());
    CenterWindow(hDlg);
    return TRUE;
}

static INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        return OnInitDialog(hDlg);

    case WM_SYSBIN_STATUS:
        SetDlgItemTextW(hDlg, IDC_STATUS, (LPCWSTR)lParam);
        return TRUE;

    case WM_SIZE:
        OnMainSize(hDlg);
        return TRUE;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mm = (MINMAXINFO*)lParam;
        double ux, uy;
        GetDlgUnitScale(hDlg, ux, uy);
        mm->ptMinTrackSize.x = (LONG)(540 * ux);
        mm->ptMinTrackSize.y = (LONG)(380 * uy);
        return TRUE;
    }

    case WM_NOTIFY:
    {
        NMHDR* nm = (NMHDR*)lParam;
        if (nm && nm->hwndFrom == g_hTab && nm->code == TCN_SELCHANGE)
        {
            int sel = TabCtrl_GetCurSel(g_hTab);
            for (int i = 0; i < 3; ++i)
                if (g_hPages[i])
                    ShowWindow(g_hPages[i], i == sel ? SW_SHOW : SW_HIDE);
            if (sel >= 0 && sel < 3)
            {
                std::wstring s = std::wstring(L"当前模块：") + g_tabNames[sel];
                SetStatusText(s.c_str());
            }
        }
        return TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        EndDialog(hDlg, 0);
        return TRUE;
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int)
{
    g_hInst = hInstance;

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_TAB_CLASSES | ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES |
                 ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    DialogBoxParamW(hInstance, MAKEINTRESOURCE(IDD_MAIN), nullptr, MainDlgProc, 0);
    return 0;
}
