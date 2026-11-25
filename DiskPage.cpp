#include "Sysbin.h"
#include "resource.h"
#include <winsvc.h>
#include <cstdarg>
#include <cstring>
#include <map>
#include <algorithm>

#define TARGET_TEMP      0x0001
#define TARGET_WINTEMP   0x0002
#define TARGET_RECYCLE   0x0004
#define TARGET_PREFETCH  0x0008
#define TARGET_THUMBS    0x0010
#define TARGET_BROWSER   0x0020
#define TARGET_UPDATE    0x0040
#define TARGET_JUNK      0x0080

#define WM_SYSBIN_DISKPROGRESS (WM_APP + 10)
#define WM_SYSBIN_DISKDONE     (WM_APP + 11)

#define MAX_JUNK_DEPTH    20
#define MAX_SCAN_FILES    2000000
#define MAX_JUNK_FILES    300000
#define JUNK_SAMPLE_LIMIT 20
#define PROGRESS_STEP     5000
#define CONTENT_SNIFF_BYTES 2048

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

struct JunkFile
{
    std::wstring path;
    ULONGLONG bytes = 0;
    std::wstring reason;   // why it was classified as junk
};

struct JunkResult
{
    std::vector<JunkFile> files;
    ULONGLONG bytes = 0;
    DWORD count = 0;
};

struct DiskWorkCtx
{
    HWND hDlg = nullptr;
    DWORD mask = 0;
    std::wstring drive;   // empty = all fixed drives
    bool junkScan = false;
    bool clean = false;
};

struct DiskWorkResult
{
    ScanResult fixed;
    JunkResult junk;
    std::vector<std::wstring> lines;
    std::wstring summary;
    bool clean = false;
};

struct JunkScanCtx
{
    HWND hDlg = nullptr;
    std::vector<std::wstring> skipPrefixes;
    JunkResult* result = nullptr;
    DWORD scanned = 0;
    DWORD lastProgress = 0;
    DWORD protectedDirs = 0;   // skipped dependency caches / installed tools
};

static ULONGLONG FileSizeOf(const WIN32_FIND_DATAW& fd)
{
    return ((ULONGLONG)fd.nFileSizeHigh << 32) | (ULONGLONG)fd.nFileSizeLow;
}

static bool IsDots(const wchar_t* name)
{
    return wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0;
}

static wchar_t LowerAscii(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

// Only fold ASCII letters; Chinese characters and path separators stay intact.
static std::wstring ToLowerAscii(const std::wstring& s)
{
    std::wstring r = s;
    for (wchar_t& c : r)
        c = LowerAscii(c);
    return r;
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

static void HandleRecycleBin(ScanResult& result, bool clean, const wchar_t* driveRoot = nullptr)
{
    if (clean)
    {
        HRESULT hr = SHEmptyRecycleBinW(nullptr, driveRoot,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        if (SUCCEEDED(hr))
            result.files = 1; // approximate: recycle bin is emptied as a whole
        return;
    }

    SHQUERYRBINFO info;
    ZeroMemory(&info, sizeof(info));
    info.cbSize = sizeof(info);
    if (SUCCEEDED(SHQueryRecycleBinW(driveRoot, &info)))
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
    if (IsDlgButtonChecked(hDlg, IDC_CK_JUNKSCAN) == BST_CHECKED) mask |= TARGET_JUNK;
    return mask;
}

static void AddLogLine(std::vector<std::wstring>& lines, const wchar_t* text)
{
    lines.push_back(text);
}

static void AddLogFmt(std::vector<std::wstring>& lines, const wchar_t* fmt, ...)
{
    wchar_t buf[1024] = { 0 };
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, 1024, fmt, args);
    va_end(args);
    lines.push_back(buf);
}

// ---------------- Automatic junk-file recognition ----------------

// File types that are never deleted, no matter where they live. This protects
// source code, documents, media and archives from aggressive content rules.
static const wchar_t* const PROTECTED_EXTS[] = {
    L".c", L".cc", L".cpp", L".cxx", L".h", L".hh", L".hpp", L".hxx", L".inl",
    L".cs", L".java", L".kt", L".kts", L".swift", L".m", L".mm", L".go", L".rs",
    L".py", L".js", L".jsx", L".ts", L".tsx", L".vue", L".php", L".rb", L".pl",
    L".sql", L".html", L".htm", L".css", L".scss", L".less", L".razor", L".asp",
    L".aspx", L".json", L".xml", L".yaml", L".yml", L".toml", L".ini", L".cfg",
    L".conf", L".config", L".properties", L".md", L".txt", L".rtf", L".csv",
    L".rc", L".rc2", L".sln", L".vcxproj", L".csproj", L".pyproj", L".props",
    L".targets", L".gitignore", L".gitattributes", L".sh", L".bat", L".ps1",
    L".png", L".jpg", L".jpeg", L".gif", L".bmp", L".ico", L".svg", L".webp",
    L".mp3", L".wav", L".flac", L".mp4", L".avi", L".mkv", L".mov", L".wmv",
    L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2", L".xz", L".iso",
    L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".odt",
    L".psd", L".ai", L".ttf", L".otf", L".pem", L".cer", L".pfx", L".key"
};

// Disposable by name alone, regardless of location.
static const wchar_t* const STRONG_JUNK_EXTS[] = {
    L".tmp", L".temp", L".dmp", L".etl", L".crdownload", L".part", L".partial",
    L".old", L".cache", L".chk", L".gid", L".pyc", L".pyo",
    L".obj", L".pdb", L".ilk", L".idb", L".pch", L".tlog", L".tli", L".tlh",
    L".exp", L".res", L".sdf", L".opensdf", L".suo", L".ncb", L".aps", L".bsc",
    L".ipch", L".dmp", L".mdmp"
};

// Generated build output: only treated as junk inside a verified build directory.
// Downloaded packages such as .nupkg live under dependency caches that are
// skipped entirely, so they can never reach this rule.
static const wchar_t* const BUILD_ARTIFACT_EXTS[] = {
    L".dll", L".exe", L".lib", L".a", L".o", L".so", L".dylib",
    L".class", L".jar", L".war", L".ear", L".apk", L".aab",
    L".map", L".bundle", L".pak", L".bin", L".dat", L".db", L".sqlite"
};

static bool ExtIn(const std::wstring& ext, const wchar_t* const* list, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (ext == list[i])
            return true;
    }
    return false;
}

static bool IsProtectedExt(const std::wstring& ext)
{
    return ExtIn(ext, PROTECTED_EXTS,
        sizeof(PROTECTED_EXTS) / sizeof(PROTECTED_EXTS[0]));
}

// A project must live next to a "bin" directory before we treat its contents as
// rebuildable. This prevents installed tools such as ~/.local/bin/uv.exe from
// being mistaken for build output.
static bool HasProjectMarker(const std::wstring& parentDir)
{
    static const wchar_t* const markers[] = {
        L"*.sln", L"*.vcxproj", L"*.csproj", L"*.fsproj", L"*.vbproj",
        L"*.pyproj", L"CMakeLists.txt", L"Makefile", L"package.json",
        L"pyproject.toml", L"setup.py", L"pom.xml", L"build.gradle",
        L"build.gradle.kts", L"Cargo.toml", L"go.mod", L"*.xcodeproj",
        L"*.uproject", L"*.slnx"
    };
    for (const wchar_t* m : markers)
    {
        std::wstring pattern = parentDir + L"\\" + m;
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            FindClose(h);
            return true;
        }
    }
    return false;
}

// Directory names whose contents are genuinely regenerated by a local build.
// Generic names like "bin" and "packages" are intentionally NOT trusted here.
static bool IsBuildDirName(const std::wstring& lowerName, const std::wstring& parentDir)
{
    static const wchar_t* const dirs[] = {
        L"obj", L"debug", L"release", L"x64", L"x86", L"anycpu", L"arm64",
        L"__pycache__", L".vs", L".idea", L"target", L"dist", L"out", L"build",
        L"intermediate", L"generated", L"gen", L"testresults", L"coverage",
        L".pytest_cache", L".mypy_cache", L"cmakefiles", L"cmake-build-debug",
        L"cmake-build-release", L"ipch", L"snapshot", L"bld", L"ship"
    };
    for (const wchar_t* d : dirs)
    {
        if (lowerName == d)
            return true;
    }
    // "bin" counts only when a project file sits beside it.
    if (lowerName == L"bin")
        return HasProjectMarker(parentDir);
    return false;
}

enum class ContentKind
{
    None,
    PDB,          // Microsoft C/C++ MSF
    COFF,         // .obj intermediate
    JavaClass,    // CA FE BA BE
    Minidump,     // MDMP
    PE,           // MZ + PE signature
    Zip,          // PK\x03\x04
    OtherBinary   // contains NUL bytes, not text
};

// Genuinely open and read the file to classify it by content, not just name.
static ContentKind SniffContent(const std::wstring& path, ULONGLONG size)
{
    if (size < 16)
        return ContentKind::None;

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return ContentKind::None;

    unsigned char buf[CONTENT_SNIFF_BYTES] = { 0 };
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf, CONTENT_SNIFF_BYTES, &got, nullptr);
    CloseHandle(h);
    if (!ok || got < 16)
        return ContentKind::None;

    if (got >= 24 && memcmp(buf, "Microsoft C/C++ MSF 7.00", 24) == 0)
        return ContentKind::PDB;
    if ((buf[0] == 0x4C && buf[1] == 0x01) ||   // IMAGE_FILE_MACHINE_I386
        (buf[0] == 0x64 && buf[1] == 0x86) ||   // AMD64
        (buf[0] == 0x64 && buf[1] == 0xAA))     // ARM64
        return ContentKind::COFF;
    if (buf[0] == 0xCA && buf[1] == 0xFE && buf[2] == 0xBA && buf[3] == 0xBE)
        return ContentKind::JavaClass;
    if (memcmp(buf, "MDMP", 4) == 0 || memcmp(buf, "PMDM", 4) == 0)
        return ContentKind::Minidump;
    if (buf[0] == 'M' && buf[1] == 'Z')
    {
        DWORD pe = buf[0x3C] | (buf[0x3D] << 8) | ((DWORD)buf[0x3E] << 16) | ((DWORD)buf[0x3F] << 24);
        if (pe + 4 <= got && memcmp(buf + pe, "PE\0\0", 4) == 0)
            return ContentKind::PE;
    }
    if (buf[0] == 'P' && buf[1] == 'K' && buf[2] == 3 && buf[3] == 4)
        return ContentKind::Zip;

    for (DWORD i = 0; i < got; ++i)
    {
        if (buf[i] == 0)
            return ContentKind::OtherBinary;
    }
    return ContentKind::None;
}

// Decide with name + real file content. Returns false for protected files.
static bool DetermineJunk(const std::wstring& path, const wchar_t* fileName,
                          ULONGLONG size, bool inBuildDir, std::wstring& reason)
{
    std::wstring lower = ToLowerAscii(fileName);
    size_t dot = lower.find_last_of(L'.');
    std::wstring ext = (dot == std::wstring::npos) ? std::wstring() : lower.substr(dot);

    if (IsProtectedExt(ext))
        return false;

    if (lower.size() >= 2 && lower[0] == L'~' && lower[1] == L'$')
    {
        reason = L"Office 临时文件";
        return true;
    }
    if (lower == L"thumbs.db" || lower == L"ehthumbs.db")
    {
        reason = L"缩略图数据库";
        return true;
    }

    ContentKind kind = SniffContent(path, size);
    switch (kind)
    {
    case ContentKind::PDB:
        reason = L"内容：PDB 调试符号";
        return true;
    case ContentKind::COFF:
        reason = L"内容：COFF 目标文件";
        return true;
    case ContentKind::JavaClass:
        reason = L"内容：Java class 字节码";
        return true;
    case ContentKind::Minidump:
        reason = L"内容：崩溃转储";
        return true;
    default:
        break;
    }

    if (ExtIn(ext, STRONG_JUNK_EXTS,
              sizeof(STRONG_JUNK_EXTS) / sizeof(STRONG_JUNK_EXTS[0])))
    {
        reason = L"临时/缓存/中间文件扩展名";
        return true;
    }

    if (inBuildDir &&
        (kind == ContentKind::PE || kind == ContentKind::Zip ||
         kind == ContentKind::OtherBinary ||
         ExtIn(ext, BUILD_ARTIFACT_EXTS,
               sizeof(BUILD_ARTIFACT_EXTS) / sizeof(BUILD_ARTIFACT_EXTS[0]))))
    {
        reason = L"构建产物目录 + 内容确认";
        return true;
    }
    return false;
}

// Directory names that must never be descended into: system trees, program
// installs, dependency caches / installed tool homes (all require re-download
// to restore), and reparse points that could escape the target drive.
static bool IsSkipDirName(const std::wstring& lowerName)
{
    static const wchar_t* const skip[] = {
        L"windows", L"program files", L"program files (x86)", L"programdata",
        L"system volume information", L"$recycle.bin", L"recovery",
        L"boot", L"efi", L"$windows.~bt", L"$windows.~ws",
        L"msocache", L"perflogs", L"documents and settings",
        // Package caches and tool installations: deleting these means a
        // network download, so the junk scanner leaves them completely alone.
        L".nuget", L".local", L".m2", L".cargo", L".gradle", L".dotnet",
        L".rustup", L".npm", L".yarn", L".pnpm-store", L".conda",
        L".anaconda", L".sdkman", L".cache", L"node_modules",
        L"site-packages", L".venv", L"venv", L"miniconda3", L"anaconda3"
    };
    for (const wchar_t* s : skip)
    {
        if (lowerName == s)
            return true;
    }
    return false;
}

static std::vector<std::wstring> BuildSkipPrefixes()
{
    std::vector<std::wstring> prefixes;
    auto add = [&](const std::wstring& path)
    {
        if (path.empty())
            return;
        std::wstring t = ToLowerAscii(path);
        while (!t.empty() && (t.back() == L'\\' || t.back() == L'/'))
            t.pop_back();
        if (!t.empty())
            prefixes.push_back(t);
    };

    wchar_t tempBuf[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempBuf);
    add(tempBuf);

    std::wstring windir = GetEnvPath(L"WINDIR");
    add(windir + L"\\Temp");
    add(windir + L"\\Prefetch");
    add(windir + L"\\SoftwareDistribution\\Download");

    std::wstring local = GetEnvPath(L"LOCALAPPDATA");
    add(local + L"\\Microsoft\\Windows\\Explorer");
    add(local + L"\\Google\\Chrome\\User Data");
    add(local + L"\\Microsoft\\Edge\\User Data");
    add(local + L"\\Mozilla\\Firefox\\Profiles");
    return prefixes;
}

static bool IsUnderPrefix(const std::wstring& pathLower,
                          const std::vector<std::wstring>& prefixes)
{
    for (const std::wstring& p : prefixes)
    {
        if (pathLower.size() > p.size() &&
            pathLower.compare(0, p.size(), p) == 0 &&
            pathLower[p.size()] == L'\\')
            return true;
    }
    return false;
}

static void ScanJunkTree(const std::wstring& dir, int depth, JunkScanCtx& ctx,
                         bool inBuildDir = false)
{
    if (depth > MAX_JUNK_DEPTH || ctx.scanned >= MAX_SCAN_FILES)
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
        std::wstring lowerFull = ToLowerAscii(full);
        if (IsUnderPrefix(lowerFull, ctx.skipPrefixes))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;
            std::wstring lowerName = ToLowerAscii(fd.cFileName);
            if (IsSkipDirName(lowerName))
            {
                ++ctx.protectedDirs;
                continue;
            }
            ScanJunkTree(full, depth + 1, ctx,
                inBuildDir || IsBuildDirName(lowerName, dir));
        }
        else
        {
            ++ctx.scanned;
            if (ctx.scanned - ctx.lastProgress >= PROGRESS_STEP)
            {
                ctx.lastProgress = ctx.scanned;
                if (ctx.hDlg && IsWindow(ctx.hDlg))
                    PostMessageW(ctx.hDlg, WM_SYSBIN_DISKPROGRESS,
                        (WPARAM)ctx.scanned, 0);
            }
            if (ctx.result->files.size() >= MAX_JUNK_FILES)
                continue;

            std::wstring reason;
            if (!DetermineJunk(full, fd.cFileName, FileSizeOf(fd), inBuildDir, reason))
                continue;

            JunkFile jf;
            jf.path = full;
            jf.bytes = FileSizeOf(fd);
            jf.reason = reason;
            ctx.result->files.push_back(jf);
            ctx.result->bytes += jf.bytes;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static std::vector<std::wstring> GetFixedDrives()
{
    std::vector<std::wstring> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i)
    {
        if (!(mask & (1u << i)))
            continue;
        wchar_t root[8] = { 0 };
        swprintf_s(root, L"%c:\\", L'A' + i);
        if (GetDriveTypeW(root) == DRIVE_FIXED)
            drives.push_back(root);
    }
    return drives;
}

// ---------------- Fixed targets (unchanged behaviour, logs collected) ----------------

static void ProcessFixedTargets(DWORD mask, bool clean, ScanResult& total,
                                std::vector<std::wstring>& lines)
{
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
        if (clean)
            AddLogFmt(lines, L"%s：已清理 %s（%u 项）", label,
                FormatBytes(one.bytes).c_str(), one.files);
        else
            AddLogFmt(lines, L"%s：可释放 %s（%u 个文件）", label,
                FormatBytes(one.bytes).c_str(), one.files);
    };

    AddLogLine(lines, clean ? L"========== 开始清理 ==========" : L"========== 开始扫描 ==========");

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
}

// ---------------- Background worker ----------------

static void DoJunkWork(DiskWorkCtx& ctx, DiskWorkResult& res)
{
    JunkResult junk;
    JunkScanCtx jctx;
    jctx.hDlg = ctx.hDlg;
    jctx.skipPrefixes = BuildSkipPrefixes();
    jctx.result = &junk;

    std::vector<std::wstring> drives;
    if (ctx.drive.empty())
        drives = GetFixedDrives();
    else
        drives.push_back(ctx.drive);

    std::wstring scope;
    for (const std::wstring& d : drives)
    {
        if (!scope.empty()) scope += L", ";
        scope += d;
    }
    AddLogFmt(res.lines, L"自动识别扫描范围：%s", scope.c_str());
    AddLogLine(res.lines, L"安全保护：依赖缓存与已安装工具目录（.nuget / .local / .m2 / node_modules 等）需联网恢复，已完整跳过，不会列入清理。");

    for (const std::wstring& d : drives)
        ScanJunkTree(d, 0, jctx);

    AddLogFmt(res.lines, L"安全保护：本次共跳过 %u 个受保护目录。", jctx.protectedDirs);

    if (ctx.clean)
    {
        ScanResult removed;
        for (const JunkFile& jf : junk.files)
        {
            if (DeleteFileW(jf.path.c_str()))
            {
                removed.bytes += jf.bytes;
                ++removed.files;
            }
        }
        res.junk.bytes = removed.bytes;
        res.junk.count = removed.files;
        AddLogFmt(res.lines, L"自动识别垃圾文件：已清理 %s（%u 项）",
            FormatBytes(removed.bytes).c_str(), removed.files);
    }
    else
    {
        res.junk.bytes = junk.bytes;
        res.junk.count = (DWORD)junk.files.size();
        AddLogFmt(res.lines, L"自动识别垃圾文件：可释放 %s（%u 个文件，已检查 %u 个文件）",
            FormatBytes(junk.bytes).c_str(), (DWORD)junk.files.size(), jctx.scanned);
    }

    // Aggregate by classification reason so users see what was really found.
    struct ReasonStat { ULONGLONG bytes = 0; DWORD files = 0; };
    std::map<std::wstring, ReasonStat> stats;
    for (const JunkFile& jf : junk.files)
    {
        ReasonStat& s = stats[jf.reason];
        s.bytes += jf.bytes;
        ++s.files;
    }
    if (!stats.empty())
    {
        AddLogLine(res.lines, L"---- 按识别类型统计（内容读取 + 构建产物目录）----");
        for (const auto& kv : stats)
        {
            AddLogFmt(res.lines, L"  %s：%s（%u 个文件）",
                kv.first.c_str(), FormatBytes(kv.second.bytes).c_str(), kv.second.files);
        }
    }

    size_t sample = (std::min)(junk.files.size(), (size_t)JUNK_SAMPLE_LIMIT);
    for (size_t i = 0; i < sample; ++i)
        AddLogFmt(res.lines, L"    [%s] %s",
            junk.files[i].reason.c_str(), junk.files[i].path.c_str());
    if (junk.files.size() > sample)
        AddLogFmt(res.lines, L"    ... 其余 %u 项未逐一列出",
            (DWORD)(junk.files.size() - sample));
}

static DWORD WINAPI DiskWorkThread(LPVOID param)
{
    std::unique_ptr<DiskWorkCtx> ctx((DiskWorkCtx*)param);
    std::unique_ptr<DiskWorkResult> res(new DiskWorkResult());
    res->clean = ctx->clean;

    ProcessFixedTargets(ctx->mask & ~TARGET_JUNK, ctx->clean, res->fixed, res->lines);

    if (ctx->mask & TARGET_JUNK)
        DoJunkWork(*ctx, *res);

    ULONGLONG totalBytes = res->fixed.bytes + res->junk.bytes;
    DWORD totalFiles = res->fixed.files + res->junk.count;
    if (res->fixed.bytes == 0 && res->junk.bytes == 0)
        res->summary = L"扫描结果：没有发现可清理的垃圾文件";
    else if (ctx->clean)
    {
        wchar_t buf[256] = { 0 };
        swprintf_s(buf, L"扫描结果：本次已释放 %s（%u 项）",
            FormatBytes(totalBytes).c_str(), totalFiles);
        res->summary = buf;
    }
    else
    {
        wchar_t buf[256] = { 0 };
        swprintf_s(buf, L"扫描结果：可释放 %s（%u 个文件）",
            FormatBytes(totalBytes).c_str(), totalFiles);
        res->summary = buf;
    }

    AddLogLine(res->lines, res->summary.c_str());
    AddLogLine(res->lines, ctx->clean
        ? L"========== 清理完成 =========="
        : L"========== 扫描完成，点击“开始清理”执行 ==========");

    if (ctx->hDlg && IsWindow(ctx->hDlg))
        PostMessageW(ctx->hDlg, WM_SYSBIN_DISKDONE,
            (WPARAM)(ctx->clean ? 1 : 0), (LPARAM)res.release());
    return 0;
}

// ---------------- UI ----------------

static void PopulateDriveCombo(HWND hDlg)
{
    HWND cb = GetDlgItem(hDlg, IDC_DISK_DRIVE);
    if (!cb)
        return;
    ComboBox_ResetContent(cb);
    ComboBox_AddString(cb, L"所有固定磁盘");
    for (const std::wstring& drive : GetFixedDrives())
    {
        wchar_t label[192] = { 0 };
        ULARGE_INTEGER freeBytes = { 0 }, totalBytes = { 0 }, totalFree = { 0 };
        if (GetDiskFreeSpaceExW(drive.c_str(), &freeBytes, &totalBytes, &totalFree))
        {
            swprintf_s(label, L"%s  (可用 %s / 共 %s)", drive.c_str(),
                FormatBytes(freeBytes.QuadPart).c_str(),
                FormatBytes(totalBytes.QuadPart).c_str());
        }
        else
        {
            wcscpy_s(label, drive.c_str());
        }
        ComboBox_AddString(cb, label);
    }
    ComboBox_SetCurSel(cb, 0);
}

static std::wstring GetSelectedDrive(HWND hDlg)
{
    HWND cb = GetDlgItem(hDlg, IDC_DISK_DRIVE);
    int sel = cb ? ComboBox_GetCurSel(cb) : 0;
    if (sel <= 0)
        return std::wstring();  // all fixed drives

    wchar_t text[256] = { 0 };
    ComboBox_GetLBText(cb, sel, text);
    if (wcslen(text) >= 3)
        return std::wstring(text, 3);  // e.g. L"C:\\"
    return std::wstring();
}

static void SetDiskButtonsEnabled(HWND hDlg, BOOL enabled)
{
    EnableWindow(GetDlgItem(hDlg, IDC_DISK_SCAN), enabled);
    EnableWindow(GetDlgItem(hDlg, IDC_DISK_CLEAN), enabled);
    EnableWindow(GetDlgItem(hDlg, IDC_DISK_SELECTALL), enabled);
    EnableWindow(GetDlgItem(hDlg, IDC_DISK_SELECTNONE), enabled);
}

static void StartDiskWork(HWND hDlg, bool clean)
{
    DWORD mask = GetSelectedTargets(hDlg);
    if (mask == 0)
    {
        MessageBoxW(hDlg,
            L"请至少勾选一个清理项目，或启用“自动识别垃圾文件”。",
            L"Sysbin System Tools", MB_ICONINFORMATION);
        return;
    }

    DiskWorkCtx* ctx = new DiskWorkCtx();
    ctx->hDlg = hDlg;
    ctx->mask = mask;
    ctx->drive = GetSelectedDrive(hDlg);
    ctx->junkScan = (mask & TARGET_JUNK) != 0;
    ctx->clean = clean;

    SetDiskButtonsEnabled(hDlg, FALSE);
    SetDlgItemTextW(hDlg, IDC_DISK_SUMMARY,
        clean ? L"正在清理，请稍候..." : L"正在扫描，请稍候...");
    SetStatusText(clean ? L"正在清理磁盘垃圾..." : L"正在扫描磁盘垃圾...");

    HANDLE hThread = CreateThread(nullptr, 0, DiskWorkThread, ctx, 0, nullptr);
    if (!hThread)
    {
        delete ctx;
        SetDiskButtonsEnabled(hDlg, TRUE);
        MessageBoxW(hDlg, L"无法启动后台扫描线程。", L"Sysbin System Tools", MB_ICONERROR);
    }
    else
    {
        CloseHandle(hThread);
    }
}

static void FinishDiskWork(HWND hDlg, DiskWorkResult* result, bool clean)
{
    std::unique_ptr<DiskWorkResult> res(result);
    if (!IsWindow(hDlg))
        return;

    HWND hLog = GetDlgItem(hDlg, IDC_DISK_LOG);
    for (const std::wstring& line : res->lines)
        LogMessage(hLog, line.c_str());

    SetDlgItemTextW(hDlg, IDC_DISK_SUMMARY, res->summary.c_str());
    SetStatusText(res->summary.c_str());
    SetDiskButtonsEnabled(hDlg, TRUE);
}

INT_PTR CALLBACK DiskDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        PopulateDriveCombo(hDlg);
        CheckDlgButton(hDlg, IDC_CK_TEMP, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_WINTEMP, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_RECYCLE, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_BROWSER, BST_CHECKED);
        CheckDlgButton(hDlg, IDC_CK_JUNKSCAN, BST_CHECKED);
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
        if (wDu < 400 || hDu < 300)
            return TRUE;
        int rightX = wDu - 252;
        MoveDlgCtrlUnits(hDlg, IDC_DISK_SUMMARY, rightX, 8, 236, 18);
        MoveDlgCtrlUnits(hDlg, IDC_CK_WINTEMP, rightX, 56, 236, 18);
        MoveDlgCtrlUnits(hDlg, IDC_CK_PREFETCH, rightX, 80, 236, 18);
        MoveDlgCtrlUnits(hDlg, IDC_CK_BROWSER, rightX, 104, 236, 18);
        MoveDlgCtrlUnits(hDlg, IDC_DISK_CLEARLOG, wDu - 126, 152, 110, 26);
        MoveDlgCtrlUnits(hDlg, IDC_DISK_LOG, 8, 186, wDu - 16, hDu - 194);
        return TRUE;
    }

    case WM_SYSBIN_DISKPROGRESS:
    {
        wchar_t buf[128] = { 0 };
        swprintf_s(buf, L"正在扫描磁盘：已检查 %u 个文件...", (DWORD)wParam);
        SetDlgItemTextW(hDlg, IDC_DISK_SUMMARY, buf);
        return TRUE;
    }

    case WM_SYSBIN_DISKDONE:
        FinishDiskWork(hDlg, (DiskWorkResult*)lParam, wParam != 0);
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_DISK_SCAN:
            StartDiskWork(hDlg, false);
            return TRUE;

        case IDC_DISK_CLEAN:
            StartDiskWork(hDlg, true);
            return TRUE;

        case IDC_DISK_SELECTALL:
        case IDC_DISK_SELECTNONE:
        {
            bool select = LOWORD(wParam) == IDC_DISK_SELECTALL;
            UINT ids[] = { IDC_CK_TEMP, IDC_CK_WINTEMP, IDC_CK_RECYCLE, IDC_CK_PREFETCH,
                           IDC_CK_THUMBS, IDC_CK_BROWSER, IDC_CK_UPDATE, IDC_CK_JUNKSCAN };
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
