// Diagnostic: find which access rights make EmptyWorkingSet succeed.
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <vector>

static bool EnablePrivilege(LPCWSTR name)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp;
    ZeroMemory(&tp, sizeof(tp));
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid))
    {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(token);
    return ok;
}

static void Run(const char* label, DWORD access, bool useApi)
{
    std::vector<DWORD> ids(4096);
    DWORD needed = 0;
    EnumProcesses(&ids[0], (DWORD)(ids.size() * sizeof(DWORD)), &needed);
    ids.resize(needed / sizeof(DWORD));

    int opened = 0, trimmedOk = 0, decreased = 0, openDenied = 0, errShown = 0;
    unsigned long long freed = 0;
    for (DWORD pid : ids)
    {
        if (pid == 0 || pid == GetCurrentProcessId()) continue;
        HANDLE h = OpenProcess(access, FALSE, pid);
        if (!h) { ++openDenied; continue; }
        ++opened;
        PROCESS_MEMORY_COUNTERS a, b;
        ZeroMemory(&a, sizeof(a)); ZeroMemory(&b, sizeof(b));
        bool haveA = GetProcessMemoryInfo(h, &a, sizeof(a)) != FALSE;
        BOOL ok = useApi ? EmptyWorkingSet(h)
                         : SetProcessWorkingSetSize(h, (SIZE_T)-1, (SIZE_T)-1);
        DWORD err = ok ? 0 : GetLastError();
        if (ok)
        {
            ++trimmedOk;
            if (haveA && GetProcessMemoryInfo(h, &b, sizeof(b)) &&
                a.WorkingSetSize > b.WorkingSetSize)
            {
                ++decreased;
                freed += (unsigned long long)a.WorkingSetSize - b.WorkingSetSize;
            }
        }
        else if (errShown < 5)
        {
            char name[260] = "?";
            DWORD len = 260;
            QueryFullProcessImageNameA(h, 0, name, &len);
            printf("    fail pid=%u err=%lu (%s)\n", pid, err, name);
            ++errShown;
        }
        CloseHandle(h);
    }
    printf("%-22s opened=%3d denied=%2d ok=%3d decreased=%3d freed=%4llu MB\n",
        label, opened, openDenied, trimmedOk, decreased, freed / 1048576ULL);
}

int main()
{
    printf("SeDebugPrivilege: %s\n", EnablePrivilege(L"SeDebugPrivilege") ? "enabled" : "FAILED");
    Run("QUERY|VMOP (EmptyWS)", PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, true);
    Run("+SET_QUOTA (EmptyWS)", PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_SET_QUOTA, true);
    Run("ALL_ACCESS (EmptyWS)", PROCESS_ALL_ACCESS, true);
    Run("SET_QUOTA (SetWS)", PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_SET_QUOTA, false);
    Run("ALL_ACCESS (SetWS)", PROCESS_ALL_ACCESS, false);
    return 0;
}
