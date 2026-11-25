# Sysbin System Tools

一个纯 **C++ + Win32 API（无 MFC / 无第三方库）** 的系统维护小工具，把内存释放、硬盘清理与 Hosts 加速整合在一个标签页界面里。

## 功能

### 1. 内存释放
- 实时显示总物理内存、可用内存、使用率（每 2 秒自动刷新）。
- 一键遍历所有可访问进程并调用 `EmptyWorkingSet` 压缩工作集，把被换出的页面交还系统。
- 调用 `SetSystemFileCacheSize(-1, -1, 0)` 清理系统文件缓存。
- 带时间戳的日志，显示每个进程实际回收量。

### 2. 硬盘清理
**固定项目**（可勾选）：
- 用户临时文件 `%TEMP%`
- 系统临时文件 `%WINDIR%\Temp`
- 回收站（`SHEmptyRecycleBin`）
- Prefetch 预读缓存
- 缩略图缓存 `thumbcache_*.db`
- 浏览器缓存（Chrome / Edge 各配置文件 + Firefox `cache2`）
- Windows 更新缓存（清理时会自动停止并在结束后恢复 `wuauserv` 服务）

**选择磁盘**：页面顶部下拉框列出全部固定磁盘（附每个盘的可用/总容量），可选单个盘或“所有固定磁盘”。

**自动识别垃圾文件（新，默认开启）**：勾选后在所选磁盘上递归扫描，按文件特征识别垃圾，不再局限于固定文件夹：
- 明确无用的扩展名：`.tmp` `.temp` `.dmp` `.etl` `.crdownload` `.part` `.partial` `.old` `.cache` `.chk` `.gid`
- Office 锁文件 `~$*`、编辑器临时文件 `~*.tmp`、`Thumbs.db` / `ehthumbs.db`
- 刻意**不**把 `.log` / `.bak` 当垃圾，避免误删你可能需要的文件
- 自动跳过 `Windows`、`Program Files`、`ProgramData`、`System Volume Information`、`$Recycle.Bin` 等系统与程序目录，以及已被固定项目覆盖的路径（避免重复统计），并跳过所有目录联接/符号链接，防止跑出目标磁盘
- 上限 30 万个文件 / 16 层深度；扫描与清理在后台线程执行并实时显示进度，不卡界面

先点“扫描”预览：日志会列出可释放空间及前 20 个具体文件路径，确认后再点“开始清理”。被占用的文件会自动跳过，不会造成系统异常。

### 3. Hosts 加速
- 内置分组：GitHub、Cloudflare、公共 CDN、Steam、Google 服务（默认不勾选）。
- 勾选需要的条目后点“应用所选加速”，工具会：
  1. 首次使用时把原始 `hosts` 备份为 `hosts.sysbin.bak`；
  2. 移除旧的受管理区块，写入新的受管理区块（带明确起止标记，不破坏用户原有条目）；
  3. 自动执行 `ipconfig /flushdns`。
- “还原原始 Hosts”可一键恢复。
- **自动解析域名 IP（核心）**：勾选“自动解析域名 IP（DoH）”后，应用加速时会对每个勾选的域名现场发起 **DNS over HTTPS** 查询（WinHTTP，RFC 8484），拿到真实 A 记录再写入 hosts——绕过本地 DNS 污染，不用写死的示例 IP。可在下拉框切换 DNSPod / Cloudflare / Google / AliDNS 四个 DoH 服务器；DoH 失败会自动回退系统解析。
- “测试延迟”按钮同样走 DoH：列表的**解析 IP**列显示现场查到的地址（带 `*` 表示来自 DoH），**延迟**列显示耗时。
- **“立即查询”按钮**：对所有勾选域名强制重新做一次 DoH 解析，只刷新**解析 IP**列（延迟列显示“已解析”），不做延迟探测——想快速拿到当前 IP、不关心 ping 时用这个。解析结果同样会缓存，供后续测试/应用复用。
- **并行测试 + TCP 443 回退**：测试在 6 个后台线程中并行进行，21 条规则几秒内完成，不会卡在 `...`。延迟优先用 ICMP ping；由于多数 CDN 节点会丢弃 ICMP 包（导致“超时”），ICMP 不通时会自动改用 **TCP 443 握手**测速——更接近真实 HTTPS 访问。延迟列带 `T` 表示这是 TCP 443 探测结果，纯数字为 ICMP。解析到的 IP 会缓存，重复测试不再重新解析。
- **实时侦测 DNS 变化并自动更新 Hosts（新）**：勾选"实时侦测 DNS 变化并自动更新 Hosts"后，程序每 60 秒在后台对已加速的域名重新做一次解析。当某个域名当前写入的 IP 已不在最新 DNS 结果中（说明节点已轮换/失效）时，自动把 hosts 里的对应 IP 换成最新值并刷新 DNS 缓存——GitHub 这类 CDN 域名全球 IP 几十分钟就轮换一次，开启后无需手动维护。
  - 只对通过"自动解析"写入的条目生效；你手写的固定 IP 不会被改动。
  - CDN 通常同时返回多个 A 记录：只要当前 IP 仍在结果集中就不会动，避免轮询抖动导致频繁改写。
  - 开关状态会记住（保存在 `SysbinHosts.ini`），默认开启；关闭后后台线程立即停止。
  - 自动更新会在列表的"解析 IP"列和状态栏给出提示。
- **规则可直接编辑**：程序首次运行会在 exe 同目录生成 `SysbinHosts.ini`。取消勾选自动解析后，会用里面的 IP 写入；其中 `auto` 表示单个域名仍走自动解析。
- 界面下方的自定义框支持手写条目，格式为 `IP 域名`。

## 编译

### 方式 A：命令行（推荐）
安装 Visual Studio 2022 → “使用 C++ 的桌面开发”组件，然后双击：

```
build.bat
```

输出：`build\SysbinSystemTools.exe`

### 方式 B：Visual Studio
先确认安装时勾选了 **“使用 C++ 的桌面开发”（Desktop development with C++）**，然后打开 `SysbinSystemTools.sln`，选择 `Release | x64`，按 F7。
如果当初没勾，打开 **Visual Studio Installer → 修改 → 工作负载 → 勾选“使用 C++ 的桌面开发” → 安装**即可，装完就能编译本工程。

### 方式 C：MinGW-w64（不用装 VS 的 C++ 组件）
如果 PATH 里有 `g++` 和 `windres`（MinGW-w64），双击：

```
build-mingw.bat
```

输出同样是 `build\SysbinSystemTools.exe`。

## 运行

程序在 manifest 中声明了 `requireAdministrator`，启动时会弹出 UAC 提示，请允许。

> 编码说明：`.rc` 文件顶部有 `#pragma code_page(65001)`，C++ 源码需以 UTF-8 编译（工程文件与 `build.bat` 已配置 `/utf-8`）。若自行换编译器，请保持这两处设置，否则界面中文会变成乱码。

> **重要提示**
> - `SysbinHosts.ini` 中的 IP 是示例值，DNS 会变化。建议用“测试延迟”验证后，把表现最好的 IP 写回 ini。
> - 若安全软件拦截 hosts 写入，请先暂时允许，或手动用“打开 Hosts”查看结果。
> - 清理系统临时文件时，正在使用的文件会被跳过，这是正常行为。

## 源码结构

| 文件 | 说明 |
| --- | --- |
| `Main.cpp` | WinMain、主对话框、Tab 控件、状态栏、布局 |
| `Common.cpp` | 通用工具函数（日志、权限、路径、DNS 刷新） |
| `MemoryPage.cpp` | 内存状态与释放 |
| `DiskPage.cpp` | 扫描与清理逻辑 |
| `HostsPage.cpp` | Hosts 规则管理、备份还原、Ping 测试 |
| `Sysbin.h` / `resource.h` | 公共声明与资源 ID |
| `SysbinSystemTools.rc` / `app.manifest` | 对话框资源、UAC 清单 |
| `tools/make_icon.py` | 生成 `sysbin.ico` 的无依赖脚本 |
