#include "Sysbin.h"
#include "resource.h"
#include <icmpapi.h>
#include <winhttp.h>
#include <map>
#pragma comment(lib, "winhttp.lib")

#define WM_SYSBIN_PINGRESULT  (WM_APP + 2)
#define WM_SYSBIN_PINGDONE    (WM_APP + 3)
#define WM_SYSBIN_APPLYRESULT (WM_APP + 4)
#define WM_SYSBIN_WATCHRESULT (WM_APP + 5)

#define HOSTS_START "# >>> Sysbin System Tools - Managed Acceleration START >>>"
#define HOSTS_END   "# <<< Sysbin System Tools - Managed Acceleration END <<<"
// Appended to auto-resolved hosts lines so the watcher knows which ones it owns.
#define HOSTS_AUTO_TAG " # sysbin:auto"
#define WATCH_INTERVAL_SEC 60

struct HostEntry
{
    std::wstring section;
    std::wstring domain;
    std::wstring ip;
    std::wstring resolvedIp;   // cached result of DoH / system resolution
    bool fromDoh = false;
};

static std::vector<HostEntry> g_entries;

// Shared by the apply / restore paths and the background DNS watcher so that
// hosts-file read-modify-write operations never interleave.
static CRITICAL_SECTION g_hostsCs;
static bool g_csReady = false;

static const wchar_t* SECTIONS[] = {
    L"GitHub", L"Cloudflare", L"公共CDN", L"Steam", L"Google服务"
};
static const size_t SECTION_COUNT = sizeof(SECTIONS) / sizeof(SECTIONS[0]);

static const wchar_t* DEFAULT_ENTRIES[][3] = {
    { L"GitHub",      L"github.com",                    L"140.82.112.3" },
    { L"GitHub",      L"gist.github.com",               L"140.82.114.4" },
    { L"GitHub",      L"codeload.github.com",           L"192.30.255.116" },
    { L"GitHub",      L"raw.githubusercontent.com",     L"185.199.108.133" },
    { L"GitHub",      L"assets-cdn.github.com",         L"185.199.108.133" },
    { L"GitHub",      L"github.global.ssl.fastly.net",  L"151.101.1.194" },

    { L"Cloudflare",  L"cloudflare.com",                L"104.16.132.229" },
    { L"Cloudflare",  L"www.cloudflare.com",            L"104.16.133.229" },
    { L"Cloudflare",  L"cdnjs.cloudflare.com",          L"104.17.24.14" },

    { L"\u516c\u5171CDN", L"cdn.jsdelivr.net",          L"151.101.1.229" },
    { L"\u516c\u5171CDN", L"unpkg.com",                 L"104.18.122.25" },
    { L"\u516c\u5171CDN", L"fonts.googleapis.com",      L"142.250.75.138" },
    { L"\u516c\u5171CDN", L"fonts.gstatic.com",         L"142.250.75.138" },
    { L"\u516c\u5171CDN", L"ajax.googleapis.com",       L"142.250.75.138" },

    { L"Steam",       L"store.steampowered.com",        L"104.102.213.212" },
    { L"Steam",       L"steamcommunity.com",            L"104.102.213.212" },
    { L"Steam",       L"media.steampowered.com",        L"104.102.213.212" },
    { L"Steam",       L"cdn.akamai.steamstatic.com",    L"104.102.213.212" },

    { L"Google\u670d\u52a1", L"www.google.com",         L"142.250.75.138" },
    { L"Google\u670d\u52a1", L"drive.google.com",       L"142.250.75.138" },
    { L"Google\u670d\u52a1", L"www.youtube.com",        L"142.250.75.138" },
};
static const size_t DEFAULT_ENTRY_COUNT =
    sizeof(DEFAULT_ENTRIES) / sizeof(DEFAULT_ENTRIES[0]);

static std::string ToUtf8(const std::wstring& text)
{
    if (text.empty())
        return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
        nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return std::string();
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
        &out[0], len, nullptr, nullptr);
    return out;
}

static std::wstring FromUtf8(const std::string& text)
{
    if (text.empty())
        return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(),
        nullptr, 0);
    if (len <= 0)
        return std::wstring();
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.size(), &out[0], len);
    return out;
}

static std::wstring Trim(const std::wstring& s)
{
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos)
        return std::wstring();
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

static void WriteDefaultIni(const std::wstring& ini)
{
    for (size_t i = 0; i < SECTION_COUNT; ++i)
    {
        WritePrivateProfileStringW(SECTIONS[i], nullptr, nullptr, ini.c_str());
        for (size_t j = 0; j < DEFAULT_ENTRY_COUNT; ++j)
        {
            if (wcscmp(DEFAULT_ENTRIES[j][0], SECTIONS[i]) == 0)
                WritePrivateProfileStringW(SECTIONS[i], DEFAULT_ENTRIES[j][1],
                    DEFAULT_ENTRIES[j][2], ini.c_str());
        }
    }
}

static void LoadEntries()
{
    g_entries.clear();
    std::wstring ini = GetIniPath();
    if (GetFileAttributesW(ini.c_str()) == INVALID_FILE_ATTRIBUTES)
        WriteDefaultIni(ini);

    std::vector<wchar_t> buffer(65536, 0);
    for (size_t i = 0; i < SECTION_COUNT; ++i)
    {
        DWORD len = GetPrivateProfileSectionW(SECTIONS[i], &buffer[0],
            (DWORD)buffer.size(), ini.c_str());
        if (len == 0)
            continue;
        wchar_t* cursor = &buffer[0];
        while (*cursor)
        {
            size_t lineLen = wcslen(cursor);
            std::wstring line(cursor, lineLen);
            cursor += lineLen + 1;

            size_t eq = line.find(L'=');
            if (eq == std::wstring::npos)
                continue;
            std::wstring domain = Trim(line.substr(0, eq));
            std::wstring ip = Trim(line.substr(eq + 1));
            if (domain.empty() || ip.empty() || domain[0] == L';')
                continue;
            HostEntry entry;
            entry.section = SECTIONS[i];
            entry.domain = domain;
            entry.ip = ip;
            g_entries.push_back(entry);
        }
    }
}

static void SetupListView(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    struct Column { const wchar_t* text; int width; };
    Column cols[] = {
        { L"分类", 70 }, { L"域名", 162 }, { L"配置 IP", 96 },
        { L"解析 IP", 96 }, { L"延迟", 60 }
    };
    LVCOLUMNW col;
    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (int i = 0; i < 5; ++i)
    {
        col.pszText = (LPWSTR)cols[i].text;
        col.cx = cols[i].width;
        col.iSubItem = i;
        ListView_InsertColumn(hList, i, &col);
    }

    for (size_t i = 0; i < g_entries.size(); ++i)
    {
        LVITEMW item;
        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = (int)i;
        item.iSubItem = 0;
        item.pszText = (LPWSTR)g_entries[i].section.c_str();
        item.lParam = (LPARAM)i;
        int row = ListView_InsertItem(hList, &item);
        if (row >= 0)
        {
            ListView_SetItemText(hList, row, 1, (LPWSTR)g_entries[i].domain.c_str());
            ListView_SetItemText(hList, row, 2, (LPWSTR)g_entries[i].ip.c_str());
            wchar_t dash[] = L"--";
            ListView_SetItemText(hList, row, 3, dash);
            ListView_SetItemText(hList, row, 4, dash);
            bool defaultOn = (g_entries[i].section != L"Google\u670d\u52a1");
            ListView_SetCheckState(hList, row, defaultOn);
        }
    }
}

static std::string ReadTextFile(const std::wstring& path)
{
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in)
        return std::string();
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool WriteTextFile(const std::wstring& path, const std::string& content)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, content.data(), (DWORD)content.size(), &written, nullptr);
    CloseHandle(h);
    return ok && written == content.size();
}

static std::string StripManagedBlock(const std::string& content)
{
    size_t start = content.find(HOSTS_START);
    if (start == std::string::npos)
        return content;

    size_t end;
    size_t markerEnd = content.find(HOSTS_END, start);
    if (markerEnd != std::string::npos)
    {
        end = markerEnd + strlen(HOSTS_END);
        while (end < content.size() && (content[end] == '\r' || content[end] == '\n'))
            ++end;
    }
    else
    {
        end = content.size();
    }
    return content.substr(0, start) + content.substr(end);
}

static UINT64 CountManagedLines(const std::string& content)
{
    size_t start = content.find(HOSTS_START);
    if (start == std::string::npos)
        return 0;
    size_t end = content.find(HOSTS_END, start);
    if (end == std::string::npos)
        return 0;
    std::string block = content.substr(start, end - start);
    std::istringstream in(block);
    std::string line;
    UINT64 count = 0;
    while (std::getline(in, line))
    {
        std::string::size_type p = line.find_first_not_of(" \t\r");
        if (p == std::string::npos || line[p] == '#')
            continue;
        ++count;
    }
    return count;
}

// ---------- DNS over HTTPS (RFC 8484) ----------
static const wchar_t* DOH_SERVERS[] = {
    L"doh.pub", L"cloudflare-dns.com", L"dns.google", L"223.5.5.5"
};
static const wchar_t* DOH_LABELS[] = {
    L"DNSPod (doh.pub)", L"Cloudflare (1.1.1.1)",
    L"Google (8.8.8.8)", L"AliDNS (223.5.5.5)"
};
static const int DOH_SERVER_COUNT = 4;

static std::string Base64Url(const std::vector<BYTE>& data)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    while (i + 2 < data.size())
    {
        DWORD v = ((DWORD)data[i] << 16) | ((DWORD)data[i + 1] << 8) | data[i + 2];
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        out += alphabet[(v >> 6) & 63];
        out += alphabet[v & 63];
        i += 3;
    }
    if (i + 1 == data.size())
    {
        DWORD v = (DWORD)data[i] << 16;
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
    }
    else if (i + 2 == data.size())
    {
        DWORD v = ((DWORD)data[i] << 16) | ((DWORD)data[i + 1] << 8);
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        out += alphabet[(v >> 6) & 63];
    }
    return out;
}

static std::vector<BYTE> BuildDnsQueryA(const std::string& domain, WORD id)
{
    std::vector<BYTE> q(12, 0);
    q[0] = (BYTE)(id >> 8);
    q[1] = (BYTE)id;
    q[2] = 0x01;              // recursion desired
    q[5] = 0x01;              // QDCOUNT = 1
    size_t pos = 0;
    while (pos < domain.size())
    {
        size_t dot = domain.find('.', pos);
        size_t len = (dot == std::string::npos) ? domain.size() - pos : dot - pos;
        q.push_back((BYTE)len);
        for (size_t k = 0; k < len; ++k)
            q.push_back((BYTE)domain[pos + k]);
        if (dot == std::string::npos)
            break;
        pos = dot + 1;
    }
    q.push_back(0);           // root
    q.push_back(0); q.push_back(1);   // QTYPE = A
    q.push_back(0); q.push_back(1);   // QCLASS = IN
    return q;
}

static bool ParseDnsAnswerA(const std::vector<BYTE>& response, std::string& ip)
{
    if (response.size() < 12)
        return false;
    int questionCount = (response[4] << 8) | response[5];
    int answerCount = (response[6] << 8) | response[7];
    size_t offset = 12;

    auto skipName = [&](size_t& p) -> bool
    {
        int hops = 0;
        while (p < response.size())
        {
            BYTE len = response[p];
            if (len == 0) { ++p; return true; }
            if ((len & 0xC0) == 0xC0) { p += 2; return true; }
            if (len > 63) return false;
            p += 1 + (size_t)len;
            if (++hops > 40) return false;
        }
        return false;
    };

    for (int i = 0; i < questionCount; ++i)
    {
        if (!skipName(offset) || offset + 4 > response.size())
            return false;
        offset += 4;
    }
    for (int i = 0; i < answerCount; ++i)
    {
        if (!skipName(offset) || offset + 10 > response.size())
            return false;
        WORD type = (WORD)((response[offset] << 8) | response[offset + 1]);
        WORD dataLen = (WORD)((response[offset + 8] << 8) | response[offset + 9]);
        offset += 10;
        if (offset + dataLen > response.size())
            return false;
        if (type == 1 && dataLen == 4)
        {
            char buffer[32] = { 0 };
            sprintf_s(buffer, "%u.%u.%u.%u", response[offset], response[offset + 1],
                response[offset + 2], response[offset + 3]);
            ip = buffer;
            return true;
        }
        offset += dataLen;
    }
    return false;
}

static bool QueryDohA(const std::string& domain, int serverIndex, std::string& ip)
{
    if (serverIndex < 0 || serverIndex >= DOH_SERVER_COUNT)
        return false;

    std::vector<BYTE> query = BuildDnsQueryA(domain, (WORD)(GetTickCount() & 0xFFFF));
    std::wstring path = std::wstring(L"/dns-query?dns=") + FromUtf8(Base64Url(query));

    HINTERNET session = WinHttpOpen(L"SysbinSystemTools/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;
    WinHttpSetTimeouts(session, 2500, 2500, 2500, 2500);

    HINTERNET connection = WinHttpConnect(session, DOH_SERVERS[serverIndex],
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection)
    {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    LPCWSTR headers = L"Accept: application/dns-message\r\n";
    bool ok = WinHttpSendRequest(request, headers, (DWORD)-1, nullptr, 0, 0, 0) &&
              WinHttpReceiveResponse(request, nullptr);

    std::vector<BYTE> response;
    if (ok)
    {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0)
        {
            size_t old = response.size();
            response.resize(old + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, &response[old], available, &read))
            {
                response.resize(old);
                ok = false;
                break;
            }
            response.resize(old + read);
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return ok && ParseDnsAnswerA(response, ip);
}

static IPAddr ResolveAddress(const std::wstring& host);

// Resolve a domain to a clean IP. DoH first (bypasses local DNS poisoning),
// then fall back to the system resolver.
static std::wstring ResolveForAccel(const std::wstring& domain, int serverIndex,
                                    bool useDoh, bool& fromDoh)
{
    std::string asciiIp;
    fromDoh = false;
    if (useDoh)
    {
        std::string name = ToUtf8(domain);
        // Try the selected server, then the next one as a fallback.
        if (QueryDohA(name, serverIndex, asciiIp) ||
            QueryDohA(name, (serverIndex + 1) % DOH_SERVER_COUNT, asciiIp))
        {
            fromDoh = true;
            return FromUtf8(asciiIp);
        }
    }
    IPAddr address = ResolveAddress(domain);
    if (address == INADDR_NONE)
        return std::wstring();
    IN_ADDR inAddr;
    inAddr.S_un.S_addr = address;
    return FromUtf8(inet_ntoa(inAddr));
}

// Collect every A record in a DNS response (CDN domains publish several IPs).
static bool ParseDnsAnswerAllA(const std::vector<BYTE>& response, std::vector<std::string>& ips)
{
    if (response.size() < 12)
        return false;
    int questionCount = (response[4] << 8) | response[5];
    int answerCount = (response[6] << 8) | response[7];
    size_t offset = 12;

    auto skipName = [&](size_t& p) -> bool
    {
        int hops = 0;
        while (p < response.size())
        {
            BYTE len = response[p];
            if (len == 0) { ++p; return true; }
            if ((len & 0xC0) == 0xC0) { p += 2; return true; }
            if (len > 63) return false;
            p += 1 + (size_t)len;
            if (++hops > 40) return false;
        }
        return false;
    };

    for (int i = 0; i < questionCount; ++i)
    {
        if (!skipName(offset) || offset + 4 > response.size())
            return false;
        offset += 4;
    }
    for (int i = 0; i < answerCount; ++i)
    {
        if (!skipName(offset) || offset + 10 > response.size())
            return false;
        WORD type = (WORD)((response[offset] << 8) | response[offset + 1]);
        WORD dataLen = (WORD)((response[offset + 8] << 8) | response[offset + 9]);
        offset += 10;
        if (offset + dataLen > response.size())
            return false;
        if (type == 1 && dataLen == 4)
        {
            char buffer[32] = { 0 };
            sprintf_s(buffer, "%u.%u.%u.%u", response[offset], response[offset + 1],
                response[offset + 2], response[offset + 3]);
            ips.push_back(buffer);
        }
        offset += dataLen;
    }
    return !ips.empty();
}

static bool QueryDohAllA(const std::string& domain, int serverIndex, std::vector<std::string>& ips)
{
    if (serverIndex < 0 || serverIndex >= DOH_SERVER_COUNT)
        return false;

    std::vector<BYTE> query = BuildDnsQueryA(domain, (WORD)(GetTickCount() & 0xFFFF));
    std::wstring path = std::wstring(L"/dns-query?dns=") + FromUtf8(Base64Url(query));

    HINTERNET session = WinHttpOpen(L"SysbinSystemTools/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return false;
    WinHttpSetTimeouts(session, 2500, 2500, 2500, 2500);

    HINTERNET connection = WinHttpConnect(session, DOH_SERVERS[serverIndex],
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection)
    {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    LPCWSTR headers = L"Accept: application/dns-message\r\n";
    bool ok = WinHttpSendRequest(request, headers, (DWORD)-1, nullptr, 0, 0, 0) &&
              WinHttpReceiveResponse(request, nullptr);

    std::vector<BYTE> response;
    if (ok)
    {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available > 0)
        {
            size_t old = response.size();
            response.resize(old + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, &response[old], available, &read))
            {
                response.resize(old);
                ok = false;
                break;
            }
            response.resize(old + read);
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return ok && ParseDnsAnswerAllA(response, ips);
}

// Resolve a domain to all IPv4 addresses, DoH first, then the system resolver.
static bool ResolveAllForAccel(const std::wstring& domain, int serverIndex, bool useDoh,
                               std::vector<std::wstring>& ips)
{
    ips.clear();
    if (useDoh)
    {
        std::string name = ToUtf8(domain);
        std::vector<std::string> asciiIps;
        if (QueryDohAllA(name, serverIndex, asciiIps) ||
            QueryDohAllA(name, (serverIndex + 1) % DOH_SERVER_COUNT, asciiIps))
        {
            for (const std::string& s : asciiIps)
                ips.push_back(FromUtf8(s));
            if (!ips.empty())
                return true;
        }
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string ascii = ToUtf8(domain);
    addrinfo* addresses = nullptr;
    if (getaddrinfo(ascii.c_str(), nullptr, &hints, &addresses) == 0 && addresses)
    {
        for (addrinfo* ai = addresses; ai; ai = ai->ai_next)
        {
            sockaddr_in* sin = (sockaddr_in*)ai->ai_addr;
            ips.push_back(FromUtf8(inet_ntoa(sin->sin_addr)));
        }
        freeaddrinfo(addresses);
    }
    WSACleanup();
    return !ips.empty();
}

static IPAddr ResolveAddress(const std::wstring& host)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    IPAddr result = INADDR_NONE;
    addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string ascii = ToUtf8(host);
    addrinfo* addresses = nullptr;
    if (getaddrinfo(ascii.c_str(), nullptr, &hints, &addresses) == 0 && addresses)
    {
        sockaddr_in* sin = (sockaddr_in*)addresses->ai_addr;
        result = sin->sin_addr.S_un.S_addr;
        freeaddrinfo(addresses);
    }
    WSACleanup();
    return result;
}

static int PingAddress(IPAddr address)
{
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE)
        return -1;
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + 256;
    std::vector<BYTE> buffer(replySize);
    const char payload[] = "sysbin";
    DWORD replies = IcmpSendEcho(icmp, address, (LPVOID)payload, (WORD)(sizeof(payload) - 1),
        nullptr, &buffer[0], replySize, 600);
    int latency = -1;
    if (replies > 0)
    {
        ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)&buffer[0];
        if (reply->Status == IP_SUCCESS)
            latency = (int)reply->RoundTripTime;
    }
    IcmpCloseHandle(icmp);
    return latency;
}

// Measure reachability via a TCP handshake to port 443. Most CDN nodes drop
// ICMP echo requests but still accept HTTPS connections, so this is a much
// better indicator of whether the acceleration entry actually works.
static int TcpProbe443(const std::wstring& ip)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    IPAddr address = inet_addr(ToUtf8(ip).c_str());
    if (address == INADDR_NONE)
    {
        WSACleanup();
        return -1;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);

    sockaddr_in target;
    ZeroMemory(&target, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(443);
    target.sin_addr.S_un.S_addr = address;

    DWORD start = GetTickCount();
    int rc = connect(s, (sockaddr*)&target, sizeof(target));
    int elapsed = (int)(GetTickCount() - start);
    int result = -1;

    if (rc == 0)
    {
        result = elapsed;
    }
    else if (WSAGetLastError() == WSAEWOULDBLOCK)
    {
        fd_set writeSet, exceptSet;
        FD_ZERO(&writeSet);
        FD_SET(s, &writeSet);
        FD_ZERO(&exceptSet);
        FD_SET(s, &exceptSet);
        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 500000;
        if (select(0, nullptr, &writeSet, &exceptSet, &tv) > 0 && FD_ISSET(s, &writeSet))
        {
            int error = 0;
            int errorSize = sizeof(error);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&error, &errorSize);
            if (error == 0)
                result = (int)(GetTickCount() - start);
        }
    }

    closesocket(s);
    WSACleanup();
    return result;
}

struct PingOutcome
{
    int index;
    int latency;
    int method;   // 0 = ICMP, 1 = TCP 443, -1 = query only (resolve time)
    std::wstring ip;
    bool fromDoh;
    bool resolved;
    bool queryOnly;
};

struct PingContext
{
    HWND hDlg;
    std::vector<int> indices;
    int serverIndex;
    bool useDoh;
    bool queryOnly;   // forced fresh resolve, no latency probing
    int threadCount;
    volatile LONG threadsLeft;
};

struct PingJob
{
    PingContext* ctx;
    int threadId;
};

static DWORD WINAPI PingThread(LPVOID parameter)
{
    std::unique_ptr<PingJob> job((PingJob*)parameter);
    PingContext* ctx = job->ctx;
    int threadId = job->threadId;

    for (size_t i = threadId; i < ctx->indices.size(); i += ctx->threadCount)
    {
        int index = ctx->indices[i];
        if (index < 0 || index >= (int)g_entries.size())
            continue;

        HostEntry& entry = g_entries[index];
        bool fromDoh = entry.fromDoh;
        // "立即查询" forces a fresh resolve; latency test may use the cache.
        std::wstring ip = ctx->queryOnly ? std::wstring() : entry.resolvedIp;
        bool resolved = !ip.empty();
        if (!resolved)
        {
            ip = ResolveForAccel(entry.domain, ctx->serverIndex, ctx->useDoh, fromDoh);
            if (!ip.empty())
            {
                entry.resolvedIp = ip;
                entry.fromDoh = fromDoh;
                resolved = true;
            }
        }

        int latency = -1;
        int method = -1;
        if (ctx->queryOnly)
        {
            // No probing: latency field will show the resolve source instead.
        }
        else if (!ip.empty())
        {
            IPAddr address = inet_addr(ToUtf8(ip).c_str());
            if (address != INADDR_NONE)
            {
                latency = PingAddress(address);
                method = 0;
                if (latency < 0)
                {
                    latency = TcpProbe443(ip);
                    method = 1;
                }
            }
        }

        PingOutcome* outcome = new PingOutcome;
        outcome->index = index;
        outcome->latency = latency;
        outcome->method = method;
        outcome->ip = ip;
        outcome->fromDoh = fromDoh;
        outcome->resolved = resolved;
        outcome->queryOnly = ctx->queryOnly;
        PostMessageW(ctx->hDlg, WM_SYSBIN_PINGRESULT, (WPARAM)index, (LPARAM)outcome);
    }

    if (InterlockedDecrement(&ctx->threadsLeft) == 0)
    {
        PostMessageW(ctx->hDlg, WM_SYSBIN_PINGDONE, ctx->queryOnly ? 1 : 0, 0);
        delete ctx;
    }
    return 0;
}

static void RefreshHostsStatus(HWND hDlg)
{
    std::wstring hosts = GetHostsPath();
    std::wstring backup = hosts + L".sysbin.bak";
    std::string content = ReadTextFile(hosts);
    UINT64 active = CountManagedLines(content);
    bool hasBackup = GetFileAttributesW(backup.c_str()) != INVALID_FILE_ATTRIBUTES;

    wchar_t text[512] = { 0 };
    swprintf_s(text, L"Hosts 加速：%s  |  已写入规则：%llu 条  |  原始备份：%s  |  配置文件：SysbinHosts.ini",
        active ? L"已启用" : L"未启用", active, hasBackup ? L"存在" : L"尚未创建");
    SetDlgItemTextW(hDlg, IDC_HOSTS_STATUS, text);
}

struct ApplyContext
{
    HWND hDlg;
    std::vector<int> indices;
    std::vector<std::wstring> customLines;
    int serverIndex;
    bool useDoh;
};

struct ApplyOutcome
{
    std::string block;
    int selected;
    int fromDoh;
    int fallback;
    int failed;
    std::vector<std::pair<int, std::wstring>> resolved;
};

static DWORD WINAPI ApplyThread(LPVOID parameter)
{
    std::unique_ptr<ApplyContext> ctx((ApplyContext*)parameter);
    ApplyOutcome* out = new ApplyOutcome;
    out->block = HOSTS_START;
    out->block += "\n# Generated by Sysbin System Tools - do not edit between markers\n";
    out->selected = out->fromDoh = out->fallback = out->failed = 0;

    for (int index : ctx->indices)
    {
        if (index < 0 || index >= (int)g_entries.size())
            continue;
        const HostEntry& entry = g_entries[index];
        std::wstring ip;
        bool fromDoh = false;

        if (ctx->useDoh)
        {
            ip = ResolveForAccel(entry.domain, ctx->serverIndex, true, fromDoh);
        }
        else
        {
            ip = entry.ip;
            if (Trim(ip) == L"auto")
                ip = ResolveForAccel(entry.domain, ctx->serverIndex, true, fromDoh);
        }

        if (ip.empty())
        {
            ++out->failed;
            continue;
        }
        if (fromDoh) ++out->fromDoh;
        else if (ctx->useDoh) ++out->fallback;

        // Cache the resolved IP so a later latency test does not re-resolve.
        g_entries[index].resolvedIp = ip;
        g_entries[index].fromDoh = fromDoh;

        // Mark lines whose IP came from a live DNS lookup so the watcher can
        // refresh them later. Fixed IPs supplied by the user are left alone.
        bool dynamic = ctx->useDoh || Trim(entry.ip) == L"auto";
        std::string line = ToUtf8(ip) + " " + ToUtf8(entry.domain);
        if (dynamic)
            line += HOSTS_AUTO_TAG;
        out->block += line + "\n";
        out->resolved.push_back(std::make_pair(index, ip));
        ++out->selected;
    }

    for (const std::wstring& line : ctx->customLines)
    {
        out->block += ToUtf8(line) + "\n";
        ++out->selected;
    }
    out->block += HOSTS_END;
    out->block += "\n";

    PostMessageW(ctx->hDlg, WM_SYSBIN_APPLYRESULT, 0, (LPARAM)out);
    return 0;
}

static void StartApply(HWND hDlg)
{
    HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);
    ApplyContext* ctx = new ApplyContext;
    ctx->hDlg = hDlg;
    ctx->serverIndex = (int)SendMessageW(GetDlgItem(hDlg, IDC_HOSTS_DOH), CB_GETCURSEL, 0, 0);
    ctx->useDoh = IsDlgButtonChecked(hDlg, IDC_HOSTS_AUTO) == BST_CHECKED;

    for (size_t i = 0; i < g_entries.size(); ++i)
        if (ListView_GetCheckState(hList, (int)i))
            ctx->indices.push_back((int)i);

    wchar_t customBuf[8192] = { 0 };
    GetDlgItemTextW(hDlg, IDC_HOSTS_CUSTOM, customBuf, 8192);
    std::wstring customText(customBuf);
    std::wistringstream customStream(customText);
    std::wstring line;
    while (std::getline(customStream, line))
    {
        line = Trim(line);
        if (line.empty() || line[0] == L'#' ||
            line.find_first_of(L" \t") == std::wstring::npos)
            continue;
        ctx->customLines.push_back(line);
    }

    if (ctx->indices.empty() && ctx->customLines.empty())
    {
        delete ctx;
        MessageBoxW(hDlg, L"请先勾选条目或填写自定义规则。", L"Sysbin System Tools", MB_ICONINFORMATION);
        return;
    }

    HANDLE thread = CreateThread(nullptr, 0, ApplyThread, ctx, 0, nullptr);
    if (!thread)
    {
        delete ctx;
        SetStatusText(L"无法创建解析线程。");
        return;
    }
    CloseHandle(thread);
    SetStatusText(L"正在解析域名 IP 并生成 Hosts 规则，请稍候...");
}

static void FinishApply(HWND hDlg, ApplyOutcome* outcome)
{
    std::unique_ptr<ApplyOutcome> out(outcome);
    HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);

    // Show the freshly resolved IP back in the list.
    for (const std::pair<int, std::wstring>& item : out->resolved)
    {
        std::wstring ip = item.second;
        ListView_SetItemText(hList, item.first, 3, (LPWSTR)ip.c_str());
    }

    std::wstring hosts = GetHostsPath();
    std::wstring backup = hosts + L".sysbin.bak";

    EnterCriticalSection(&g_hostsCs);
    std::string original = ReadTextFile(hosts);
    if (GetFileAttributesW(backup.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        if (!CopyFileW(hosts.c_str(), backup.c_str(), TRUE))
        {
            LeaveCriticalSection(&g_hostsCs);
            MessageBoxW(hDlg, L"无法创建原始 Hosts 备份，已取消写入。\n请确认以管理员身份运行。",
                L"Sysbin System Tools", MB_ICONERROR);
            return;
        }
    }

    std::string updated = StripManagedBlock(original);
    if (!updated.empty() && updated.back() != '\n')
        updated += "\n";
    updated += "\n";
    updated += out->block;

    bool written = WriteTextFile(hosts, updated);
    LeaveCriticalSection(&g_hostsCs);

    if (!written)
    {
        MessageBoxW(hDlg, L"写入 Hosts 文件失败。\n请确认以管理员身份运行，且文件未被安全软件锁定。",
            L"Sysbin System Tools", MB_ICONERROR);
        return;
    }

    bool flushed = FlushDnsCache();
    wchar_t msg[320] = { 0 };
    swprintf_s(msg, L"已写入 %d 条规则（DoH 解析 %d 条，系统回退 %d 条，失败 %d 条），DNS 缓存%s。",
        out->selected, out->fromDoh, out->fallback, out->failed,
        flushed ? L"已刷新" : L"刷新失败");
    SetStatusText(msg);
    RefreshHostsStatus(hDlg);
}

static void RestoreHosts(HWND hDlg)
{
    std::wstring hosts = GetHostsPath();
    std::wstring backup = hosts + L".sysbin.bak";
    if (GetFileAttributesW(backup.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        MessageBoxW(hDlg, L"找不到原始 Hosts 备份文件。", L"Sysbin System Tools", MB_ICONWARNING);
        return;
    }
    EnterCriticalSection(&g_hostsCs);
    BOOL restored = CopyFileW(backup.c_str(), hosts.c_str(), FALSE);
    LeaveCriticalSection(&g_hostsCs);
    if (!restored)
    {
        MessageBoxW(hDlg, L"还原失败，请确认以管理员身份运行。", L"Sysbin System Tools", MB_ICONERROR);
        return;
    }
    FlushDnsCache();
    SetStatusText(L"已还原原始 Hosts 文件并刷新 DNS 缓存。");
    RefreshHostsStatus(hDlg);
}

// ---------- Automatic DNS watcher ----------
struct ManagedLine
{
    std::string ip;
    std::string domain;
    bool automatic;
};

struct WatchOutcome
{
    int checked = 0;
    int changed = 0;
    bool wrote = false;
    bool flushed = false;
    std::vector<std::pair<std::wstring, std::wstring>> changes; // domain, new IP
};

struct WatchState
{
    HANDLE hStop = nullptr;      // manual-reset event
    HANDLE hThread = nullptr;
    HWND hDlg = nullptr;
    int serverIndex = 0;
    bool useDoh = true;
    volatile LONG running = 0;
};
static WatchState g_watch;

static std::vector<ManagedLine> ParseManagedLines(const std::string& content)
{
    std::vector<ManagedLine> lines;
    size_t start = content.find(HOSTS_START);
    if (start == std::string::npos)
        return lines;
    size_t end = content.find(HOSTS_END, start);
    if (end == std::string::npos)
        end = content.size();
    std::string block = content.substr(start, end - start);
    std::istringstream in(block);
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        size_t tag = line.find(HOSTS_AUTO_TAG);
        bool automatic = (tag != std::string::npos);
        std::string body = automatic ? line.substr(0, tag) : line;
        std::istringstream ls(body);
        std::string ip, domain;
        ls >> ip >> domain;
        if (ip.empty() || domain.empty() || ip[0] == '#' || domain[0] == '#')
            continue;
        ManagedLine ml;
        ml.ip = ip;
        ml.domain = domain;
        ml.automatic = automatic;
        lines.push_back(ml);
    }
    return lines;
}

// Rebuild the managed block, swapping in refreshed IPs for the marked lines.
static std::string RewriteHostsIps(const std::string& content,
                                   const std::map<std::string, std::string>& updates)
{
    size_t start = content.find(HOSTS_START);
    if (start == std::string::npos)
        return content;
    size_t end = content.find(HOSTS_END, start);
    if (end == std::string::npos)
        end = content.size();
    else
        end += strlen(HOSTS_END);

    std::string result = content.substr(0, start);
    std::string block = content.substr(start, end - start);
    std::istringstream in(block);
    std::string line;
    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string out = line;
        size_t tag = line.find(HOSTS_AUTO_TAG);
        if (tag != std::string::npos)
        {
            std::istringstream ls(line.substr(0, tag));
            std::string ip, domain;
            ls >> ip >> domain;
            std::map<std::string, std::string>::const_iterator it = updates.find(domain);
            if (!domain.empty() && it != updates.end())
                out = it->second + " " + domain + HOSTS_AUTO_TAG;
        }
        result += out;
        result += "\n";
    }
    result += content.substr(end);
    return result;
}

static DWORD WINAPI WatchThread(LPVOID)
{
    for (;;)
    {
        DWORD wait = WaitForSingleObject(g_watch.hStop, WATCH_INTERVAL_SEC * 1000);
        if (wait == WAIT_OBJECT_0 || !g_watch.running)
            break;

        WatchOutcome* out = new WatchOutcome;
        std::wstring hosts = GetHostsPath();
        EnterCriticalSection(&g_hostsCs);
        std::string content = ReadTextFile(hosts);
        std::vector<ManagedLine> lines = ParseManagedLines(content);
        std::map<std::string, std::string> updates;

        for (size_t i = 0; i < lines.size() && g_watch.running; ++i)
        {
            const ManagedLine& ml = lines[i];
            if (!ml.automatic)
                continue;
            ++out->checked;
            std::wstring domain = FromUtf8(ml.domain);
            std::vector<std::wstring> ips;
            if (!ResolveAllForAccel(domain, g_watch.serverIndex, g_watch.useDoh, ips) || ips.empty())
                continue;

            // CDN domains rotate A records. Keep the current IP as long as it is
            // still among the fresh answers; only switch when it went stale.
            bool stillValid = false;
            for (size_t k = 0; k < ips.size(); ++k)
            {
                if (ToUtf8(ips[k]) == ml.ip) { stillValid = true; break; }
            }
            if (stillValid)
                continue;

            std::string newIp = ToUtf8(ips[0]);
            if (newIp == ml.ip)
                continue;
            updates[ml.domain] = newIp;
            out->changes.push_back(std::make_pair(domain, ips[0]));
            ++out->changed;
        }

        if (!updates.empty() && g_watch.running)
        {
            std::string rewritten = RewriteHostsIps(content, updates);
            if (WriteTextFile(hosts, rewritten))
            {
                out->wrote = true;
                out->flushed = FlushDnsCache();
            }
        }
        LeaveCriticalSection(&g_hostsCs);

        if (g_watch.hDlg && IsWindow(g_watch.hDlg))
            PostMessageW(g_watch.hDlg, WM_SYSBIN_WATCHRESULT, 0, (LPARAM)out);
        else
            delete out;
    }
    return 0;
}

static void StartWatch(HWND hDlg, int serverIndex, bool useDoh)
{
    if (g_watch.running || !g_csReady)
        return;
    g_watch.hDlg = hDlg;
    g_watch.serverIndex = serverIndex;
    g_watch.useDoh = useDoh;
    g_watch.hStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_watch.hStop)
        return;
    g_watch.running = 1;
    g_watch.hThread = CreateThread(nullptr, 0, WatchThread, nullptr, 0, nullptr);
    if (!g_watch.hThread)
    {
        g_watch.running = 0;
        CloseHandle(g_watch.hStop);
        g_watch.hStop = nullptr;
        return;
    }
    wchar_t msg[200];
    swprintf_s(msg, L"实时侦测已开启：每 %d 秒检查一次已加速域名的 IP，发生变化时自动更新 Hosts。",
        WATCH_INTERVAL_SEC);
    SetStatusText(msg);
}

static void StopWatch()
{
    g_watch.running = 0;
    if (g_watch.hStop)
        SetEvent(g_watch.hStop);
    if (g_watch.hThread)
    {
        WaitForSingleObject(g_watch.hThread, 20000);
        CloseHandle(g_watch.hThread);
        g_watch.hThread = nullptr;
    }
    if (g_watch.hStop)
    {
        CloseHandle(g_watch.hStop);
        g_watch.hStop = nullptr;
    }
    g_watch.hDlg = nullptr;
}

static void StartResolve(HWND hDlg, bool queryOnly)
{
    HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);
    PingContext* ctx = new PingContext;
    ctx->hDlg = hDlg;
    ctx->queryOnly = queryOnly;
    ctx->serverIndex = (int)SendMessageW(GetDlgItem(hDlg, IDC_HOSTS_DOH), CB_GETCURSEL, 0, 0);
    ctx->useDoh = IsDlgButtonChecked(hDlg, IDC_HOSTS_AUTO) == BST_CHECKED;
    for (size_t i = 0; i < g_entries.size(); ++i)
    {
        if (!ListView_GetCheckState(hList, (int)i))
            continue;
        ctx->indices.push_back((int)i);
        if (queryOnly)
        {
            ListView_SetItemText(hList, (int)i, 3, (LPWSTR)L"查询中");
        }
        else
        {
            ListView_SetItemText(hList, (int)i, 4, (LPWSTR)L"...");
        }
    }
    if (ctx->indices.empty())
    {
        delete ctx;
        SetStatusText(queryOnly ? L"请先勾选要查询的条目。" : L"请先勾选要测试的条目。");
        return;
    }

    ctx->threadCount = std::min(6, (int)ctx->indices.size());
    ctx->threadsLeft = ctx->threadCount;

    bool started = false;
    for (int t = 0; t < ctx->threadCount; ++t)
    {
        PingJob* job = new PingJob;
        job->ctx = ctx;
        job->threadId = t;
        HANDLE thread = CreateThread(nullptr, 0, PingThread, job, 0, nullptr);
        if (!thread)
        {
            delete job;
            InterlockedDecrement(&ctx->threadsLeft);
            continue;
        }
        CloseHandle(thread);
        started = true;
    }
    if (!started)
    {
        delete ctx;
        SetStatusText(L"无法创建解析线程。");
        return;
    }

    wchar_t msg[160] = { 0 };
    if (queryOnly)
        swprintf_s(msg, L"正在查询 %u 个域名的 IP（强制重新解析，跳过延迟探测）...",
            (DWORD)ctx->indices.size());
    else
        swprintf_s(msg, L"正在并行测试 %u 个域名（ICMP 不通时自动改用 TCP 443 探测）...",
            (DWORD)ctx->indices.size());
    SetStatusText(msg);
}

INT_PTR CALLBACK HostsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        HWND doh = GetDlgItem(hDlg, IDC_HOSTS_DOH);
        for (int i = 0; i < DOH_SERVER_COUNT; ++i)
            SendMessageW(doh, CB_ADDSTRING, 0, (LPARAM)DOH_LABELS[i]);
        SendMessageW(doh, CB_SETCURSEL, 0, 0);
        CheckDlgButton(hDlg, IDC_HOSTS_AUTO, BST_CHECKED);
        if (!g_csReady)
        {
            InitializeCriticalSection(&g_hostsCs);
            g_csReady = true;
        }
        // Persist the watcher preference across runs.
        {
            wchar_t flag[16] = { 0 };
            GetPrivateProfileStringW(L"Sysbin", L"Watch", L"1", flag, 16, GetIniPath().c_str());
            CheckDlgButton(hDlg, IDC_HOSTS_WATCH,
                wcscmp(flag, L"1") == 0 ? BST_CHECKED : BST_UNCHECKED);
        }
        LoadEntries();
        SetupListView(hDlg);
        RefreshHostsStatus(hDlg);
        if (IsDlgButtonChecked(hDlg, IDC_HOSTS_WATCH) == BST_CHECKED)
            StartWatch(hDlg, 0, true);
        return TRUE;
    }

    case WM_SIZE:
    {
        double ux, uy;
        GetDlgUnitScale(hDlg, ux, uy);
        int wDu = (int)(LOWORD(lParam) / ux);
        int hDu = (int)(HIWORD(lParam) / uy);
        if (wDu < 400 || hDu < 250)
            return TRUE;
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_LIST, 8, 8, wDu - 16, 160);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_OPEN, wDu - 88, 174, 80, 26);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_AUTO, 10, 208, 240, 16);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_DOH, wDu - 190, 206, 180, 90);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_WATCH, 10, 228, wDu - 20, 16);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_HINT, 10, 250, wDu - 20, 16);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_CUSTOM, 8, 268, wDu - 16, 70);
        MoveDlgCtrlUnits(hDlg, IDC_HOSTS_STATUS, 8, hDu - 30, wDu - 16, 20);
        return TRUE;
    }

    case WM_SYSBIN_PINGRESULT:
    {
        std::unique_ptr<PingOutcome> outcome((PingOutcome*)lParam);
        int index = (int)wParam;
        HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);
        std::wstring ip = outcome->ip;
        if (ip.empty())
            ip = L"解析失败";
        else if (outcome->fromDoh)
            ip += L" *";
        ListView_SetItemText(hList, index, 3, (LPWSTR)ip.c_str());
        if (outcome->queryOnly)
        {
            // Query mode: show the resolve source, not a latency figure.
            ListView_SetItemText(hList, index, 4,
                (LPWSTR)(outcome->ip.empty() ? L"失败" : L"已解析"));
            return TRUE;
        }
        wchar_t text[32] = { 0 };
        if (outcome->latency >= 0)
        {
            // "T" marks a TCP 443 measurement (ICMP was blocked).
            swprintf_s(text, outcome->method == 1 ? L"%d ms T" : L"%d ms",
                outcome->latency);
        }
        else
            wcscpy_s(text, L"超时");
        ListView_SetItemText(hList, index, 4, text);
        return TRUE;
    }

    case WM_SYSBIN_PINGDONE:
        SetStatusText(wParam
            ? L"查询完成：解析 IP 列已更新（* = DoH 解析）。"
            : L"测试完成（* = DoH 解析，T = TCP 443 探测，ICMP 被节点丢弃时会自动回退）。");
        return TRUE;

    case WM_SYSBIN_APPLYRESULT:
        FinishApply(hDlg, (ApplyOutcome*)lParam);
        return TRUE;

    case WM_SYSBIN_WATCHRESULT:
    {
        std::unique_ptr<WatchOutcome> out((WatchOutcome*)lParam);
        HWND hList = GetDlgItem(hDlg, IDC_HOSTS_LIST);
        for (size_t i = 0; i < out->changes.size(); ++i)
        {
            const std::wstring& domain = out->changes[i].first;
            const std::wstring& ip = out->changes[i].second;
            for (size_t r = 0; r < g_entries.size(); ++r)
            {
                if (_wcsicmp(g_entries[r].domain.c_str(), domain.c_str()) == 0)
                {
                    g_entries[r].resolvedIp = ip;
                    ListView_SetItemText(hList, (int)r, 3, (LPWSTR)ip.c_str());
                }
            }
        }
        if (out->changed > 0)
        {
            wchar_t text[320] = { 0 };
            swprintf_s(text, L"实时侦测：%d 个域名 IP 已变化并自动更新 Hosts（检查 %d 条，DNS 缓存%s）。",
                out->changed, out->checked, out->flushed ? L"已刷新" : L"刷新失败");
            SetStatusText(text);
        }
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_HOSTS_APPLY:
            StartApply(hDlg);
            return TRUE;

        case IDC_HOSTS_RESTORE:
            RestoreHosts(hDlg);
            return TRUE;

        case IDC_HOSTS_FLUSHDNS:
            SetStatusText(FlushDnsCache() ? L"DNS 缓存已刷新。" : L"DNS 缓存刷新失败。");
            return TRUE;

        case IDC_HOSTS_QUERY:
            StartResolve(hDlg, true);
            return TRUE;

        case IDC_HOSTS_PING:
            StartResolve(hDlg, false);
            return TRUE;

        case IDC_HOSTS_AUTO:
        case IDC_HOSTS_DOH:
            // Keep the live watcher in sync with the resolve settings.
            if (g_watch.running)
            {
                g_watch.useDoh = IsDlgButtonChecked(hDlg, IDC_HOSTS_AUTO) == BST_CHECKED;
                g_watch.serverIndex =
                    (int)SendMessageW(GetDlgItem(hDlg, IDC_HOSTS_DOH), CB_GETCURSEL, 0, 0);
            }
            break;

        case IDC_HOSTS_WATCH:
        {
            bool on = IsDlgButtonChecked(hDlg, IDC_HOSTS_WATCH) == BST_CHECKED;
            WritePrivateProfileStringW(L"Sysbin", L"Watch", on ? L"1" : L"0",
                GetIniPath().c_str());
            if (on)
            {
                int server = (int)SendMessageW(GetDlgItem(hDlg, IDC_HOSTS_DOH), CB_GETCURSEL, 0, 0);
                StartWatch(hDlg, server, IsDlgButtonChecked(hDlg, IDC_HOSTS_AUTO) == BST_CHECKED);
            }
            else
            {
                StopWatch();
                SetStatusText(L"实时侦测已关闭。");
            }
            return TRUE;
        }

        case IDC_HOSTS_OPEN:
        {
            std::wstring hosts = GetHostsPath();
            ShellExecuteW(hDlg, L"open", L"notepad.exe", hosts.c_str(), nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        }
        break;

    case WM_NCDESTROY:
        StopWatch();
        return TRUE;
    }
    return FALSE;
}
