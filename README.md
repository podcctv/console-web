# console-web (NetWatch 赛博朋克网络运维终端)

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-publish.yml/badge.svg)
![Version](https://img.shields.io/badge/version-v3.9.7-78E08F?style=flat-square&logo=git)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

`console-web` 是一个基于 [Flask](https://flask.palletsprojects.com/) 和 [psutil](https://psutil.readthedocs.io/) 构建的极简赛博朋克风格系统监控面板与网络运维终端 (`NetWatch`)。界面采用暗黑终端与玻璃拟态设计，支持实时 TCP Ping 多目标延迟趋势、IPv4/IPv6 双栈链路对比、多端响应式适配、1-Click IP 复制、ACME SSL 证书自动续期及全链路故障诊断。

<img width="1012" height="1054" alt="image" src="https://github.com/user-attachments/assets/5093b202-5b38-4929-ac9a-1db5062d863a" />

---

## 🚀 一键快速部署 (推荐)

在 Linux 服务器（Ubuntu、Debian、CentOS、Alpine 等）上直接运行以下指令，即可一键自动安装 Docker 并完成镜像部署：

```bash
curl -fsSL https://raw.githubusercontent.com/podcctv/console-web/main/deploy.sh | Sh
```

或者使用 `wget` 执行：

```bash
wget -qO- https://raw.githubusercontent.com/podcctv/console-web/main/deploy.sh | Sh
```

> 💡 **部署说明**：脚本会自动检查并安装 Docker（如未安装），从 GHCR (`ghcr.io/podcctv/console-web:latest`) 拉取预构建镜像并在 `8180` 端口运行容器，数据与证书默认自动持久化挂载至宿主机 `/opt/console-web` 目录。

---

## ✨ 核心功能

- **📊 动态 Canvas Mini-Sparklines 实时趋势线条 (`v3.5 升级`)**：
  - 在 CPU、内存、磁盘及**实时网络吞吐速率 (`NET RATE ↓/↑`)** 监控栏中内嵌 Canvas Mini-Sparkline 动态走势图，呈现极佳的拟态极客视觉效果。
- **⛶ 放大全屏监控模式 (`[ ⛶ FULLSCREEN TELEMETRY ]`)**：
  - `$ tcping --watch` 延迟图表支持一键扩展为全屏高清大屏模式，适配大屏监控看板与 NOC 运维中心。
- **💬 30-Day SLA 热力图 赛博悬浮卡片 (`Cyber SLA Hover Card`)**：
  - SLA 热力方块升级为平滑悬浮弹窗，实时浮现具体日期、可用性 %、峰值延迟及故障根因分析。
- **⚡ 内存与磁盘双层时序数据库 (TimeSeriesDB v3.4 升级)**：
  - 内置 Python 线程安全内存时序数据库，采用固定容量（1440 points / 24h）滑动窗口滚动存贮，并实现磁盘自动快照持久化（`/opt/console-web/data`），服务重启后测速历史无缝恢复。
- **🌍 优雅规范 IP 归属地自动节点命名 (`Standardized Auto Node ID v3.4 升级`)**：
  - 根据服务器出口 IP 与 ISP 自动推算生成标准无冗余的 Node ID（如 `fra-hetzner-vps01` / `hkg-aliyun-vps01` / `sjc-leaseweb-vps01` / `hgh-ct-vps01`）。
- **🚀 版本检测与 1-Click 热更新 + GitHub Actions 锁**：
  - 主界面内置版本号与 GitHub 项目链接；版本检测自动判断 SemVer 语义化逻辑，对接 GitHub Actions Docker 镜像构建状态同步锁，完成编译后解锁热更新。
- **📋 统一一键 IP 复制 (`[ COPY ALL IDENTITIES ]`)**：
  - 网络身份区域提供单一顶部复制按钮，一键提取 Listen、Egress、Visitor 及 Local 接口的结构化文本至剪贴板。

### 🟢 `v3.9.7` (2026-07-30) - Fix Global Script Variable Hoisting TDZ & Fail-safe Ping Extraction
- **🛡️ TDZ Variable Order Fix**: 将 `ALL_TARGET_KEYS` / `TARGET_CONFIG` / `getSampleLat()` 提到 `<script>` 标签最顶部，彻底解决 `fetchPings()` 异步被触发时因 Temporal Dead Zone (TDZ) 引发的 `ReferenceError`。
- **⚡ Fail-Safe API Fallback & Aggregate Latency Calculation**: `fetchPings()` 增加网络请求容错重试机制（`/api/pings` -> `/pings` 自动兜底）；当 `stats.cur` 暂时为空时自动从各探测点实时测速结果推导最新延迟，确保看板数显永不卡死在 `- ms` 状态。

### 🟢 `v3.9.6` (2026-07-30) - Permanently Visible 1-Click Auto Update & Realtime Latency Sync
- **🚀 Permanent Auto Update Button**: 顶部状态栏及 `[ ··· ]` 更多菜单常驻显示 **`[ 🚀 AUTO UPDATE ]`** 一键更新按钮，任何状态下点击均可弹窗预览 GitHub 最新提交并确认从 GitHub main 覆盖平滑重启。
- **📈 Realtime Ping Endpoint & Legend Sync**: 将前端 API 请求定位为标准的 `/api/pings`，在 `fetchPings()` 中直接从响应 Top-Level keys 抽取各节点实时延迟数值，解决在没有完整 `targets_detail` 时数据不同步问题。

### 🟢 `v3.9.5` (2026-07-30) - Fix ReferenceError Uncaught Exceptions for Target Filtering
- **📈 Target Filter Reference Error Fix**: 补全 `index.html` 中缺失声明的 `ALL_TARGET_KEYS` / `selectedTargets` 全局变量及 `toggleTargetFilter()` / `exportPingCSV()` 处理函数，解决 JS 运行时抛出 `ReferenceError` 导致 `renderCanvasChart` 执行中断、TCP Ping 延迟在页面上呈 `-ms` 状态并滞留遮罩层的硬伤。

### 🟢 `v3.9.4` (2026-07-30) - Minimal Terminal Operations Workspace Redesign
- **🎨 Minimal Terminal Operations Workspace Design Tokens**: 全面重构 design tokens (`#030705` 页面基底，降低 40% 绿框与高饱和绿色，禁止纯黑纯绿)。
- **🖥️ 3-Section Compact Header Navigation**: 顶部简化为 `NW_NETWATCH v3.9.4` / `Overview · Targets · Diagnostics · Events` / `● LIVE` / `[⌘K]`，将 GitHub、音效、主题与帮助收纳进 `[···]` 下拉菜单。
- **💻 Terminal Command Section Titles**: 全站统一采用 `$ netwatch status --summary` / `$ tcping --watch` / `$ network compare` 命令行锚点标题叙事。
- **⚡ Single-Column Hero State Summary**: Hero 区改为简洁终端状态叙事 Block，右侧配以强视觉级别的 `[ RUN FULL DIAGNOSTICS ]` 核心操作按钮。

### 🟢 `v3.9.3` (2026-07-30) - Fix TCPing "Waiting for Valid Samples" Overlay Blocking Bug
- **📈 TCPing Empty State Overlay Fix**: 修复 `fetchPings()` 中仅根据 `stats.samples_count === 0` 强制展示遮罩层的 Bug。重构为 `hasValidData = validSamplesCount > 0 || pingHistory.length > 0` 联合判定，确保存在历史数据或有效点时自动隐藏 `chart_empty_box` 遮罩，Canvas 图表立刻可见。

### 🟢 `v3.9.2` (2026-07-30) - Latency Line Chart Render Fix & Multi-Source Target Extraction
- **📈 Latency Line Chart Render Fix**: 修复 `getSampleLat()` 多维度延迟提取逻辑，解决旧磁盘历史点 `targets_detail` 为空导致 JS 条件判断把空对象估值为真、忽略 `latency` 兜底值从而引发折线图不渲染的 Bug。
- **🛡️ Null-Safe Element Controllers**: 给 `fetchPings()` 增加 `setElText` / `setElHtml` 空节点防御逻辑，防止因为特定元素 ID 丢失抛出 `TypeError` 阻断 Canvas 渲染。

### 🟢 `v3.9.1` (2026-07-30) - Telemetry Data Logic, SLA Protection & Command Palette
- **📊 Standard RFC 3550 Jitter & Threshold Engine**: 修复 Jitter 计算公式为标准连续延迟抖动，建立 Jitter 阈值评估（>100ms 标为 Critical，绝不再在 510ms 时误标 Stable）。
- **🛡️ SLA Data Coverage Protection**: 数据记录少于 30 天时显式标明 `Data coverage: X / 30 days` 并标注未满 30 天免责声明，消除数据误导。
- **⏱️ Current Health vs 1h Historical Anomaly Isolation**: 首屏显式区分当前健康状态（Healthy Now）与过去一小时历史延迟尖峰 / 已恢复事件记录。
- **⌨️ VT100 Interactive Command Palette (Ctrl+K)**：新增 `Ctrl/Cmd + K` 命令面板弹窗，支持搜索与键盘快捷操作所有运维指令。
- **🎨 Target Sequence Line & Status Color Decoupling**: 图表折线序列颜色使用中性调色盘（Blue `#6BB8FF` 等），与告警状态颜色（Red `#FF6B6B`）解耦。

### 🟢 `v3.9.0` (2026-07-30) - Visual Hierarchy Overhaul & WCAG 2.2 Accessibility Engine
- **🎯 Visual Hierarchy & Hero Primary CTA**: 引入 `<h1>` 主标题与 Hero 操作首屏 (`[ 🚀 启动全链路一键网络诊断 ]`)，构建清晰的主次次三级按钮视觉层级。
- **♿ WCAG 2.2 AA Accessibility Compliance**: 全面支持 `:focus-visible` 键盘焦点高对比度环、Skip Link 快捷跳转、HTML5 语义化 Landmark 标签 (`banner` / `navigation` / `main` / `region` / `contentinfo`) 与显式表单 `<label>` 绑定。
- **🔄 Universal State Feedback & Error Recovery**: 新增 `#global_state_feedback` 状态反馈悬浮组件，支持加载、成功、警告与带一键重试的错误恢复路径。
- **📱 3-Breakpoint Responsive Touch Optimization**: 在 1366px / 768px / 375px 断点全面提升交互触控面积 (≥ 48×48 CSS px)，消除移动端横向滚动。

### 🟢 `v3.8.1` (2026-07-29) - Dynamic Version Access & Universal Hot-Reloading Fix
- **Dynamic Version Resolution**：重构 `check_version` 与 `views.py` 中的静态 `__version__` 绑定为 `app.config.__version__` 动态提取，彻底解决热更新后版本号驻留旧值的问题。
- **Universal Module Hot-Reloading**：将模块重载与字节码缓存清理提取为 `reload_app_modules()` 共享函数，覆盖 `git pull` 与 Zip 下载双通道更新路径。

### 🟢 `v3.8.0` (2026-07-29) - Cyber Theme Selector & VT100 Quick-Cmd & Web Audio Sound FX
- **🎨 4-Palette Cyber Theme Selector**：新增 `[ 🟢 Green | 🔷 Cyan | 💖 Magenta | 🟧 Amber ]` 赛博主题霓虹配色切换器，全站 CSS 变量与光晕跟随切换。
- **🔊 Zero-Asset Web Audio Synthesizer**：基于 HTML5 `AudioContext` 实时合成 8-bit 复古 Terminal 音效 (`playCyberSound`)，支持 `[ 🔊 SOUND: ON/OFF ]` 一键切换。
- **💻 VT100 Interactive Quick Command Bar**：新增 `$ quick-cmd >` 快捷命令行胶囊条，支持一键发起系统测速、全链路诊断、导出报告与检查更新。
- **📊 Dual-Stack Jitter Telemetry Matrix**：双栈网络对比矩阵新增 `JITTER (VARIANCE ±ms)` 方差抖动列，全面剖析链路质量。

### 🟢 `v3.7.0` (2026-07-29) - Bytecode Invalidation & Memory Module Hot-Reload Engine
- **In-Memory Module Reloading**：新增 `importlib.invalidate_caches()` 及 `sys.modules` 动态热重载逻辑，在线更新完成后立刻在 Python 内存中刷刷新 `app.config.__version__` 模块。
- **stale `.pyc` Bytecode Cleanup**：热更新解压后自动清空 `__pycache__` 字节码缓存目录，配合 `SIGHUP` 信号，确保 Docker 容器/服务进程平滑重启后 100% 呈现最新版本号。

### 🟢 `v3.6.2` (2026-07-29) - Dynamic Version Injection & Click-to-Check Manual Updates
- **Dynamic Flask Version Rendering**：`views.py` 动态向 `index.html` 注入后端权威 `__version__`，彻底解决网页刷新后版本号倒退回旧版静态文本（`v3.3.0`）的问题。
- **Interactive Manual Version Check**：点击顶部导航栏版本号徽章（`#version_badge_ui`），即可触发主动在线检测，并弹窗反馈检测结果或升级指南。

### 🟢 `v3.6.1` (2026-07-29) - System Status Telemetry Layout & Grid Ratio Overhaul
- **5-Column Telemetry Grid Alignment**：重构 `$ systemctl status netwatch` 内部为标准 5 列 Grid 网格对齐（Label | Sparkline | ASCII Bar | Pct/Rate | Details），彻底消除 `load: ...` / `0.41 GB / ...` / `Rx/Tx Total` 折行与省略号打断。
- **2-Column Container Ratio Optimization**：优化主视图双列 Grid 比例为 `45% 55%`，赋予右侧系统资源监控卡片充足的展示宽度。

### 🟢 `v3.6.0` (2026-07-29) - GitHub Zip Direct Auto-Updater & Beautified Cyber Modals
- **GitHub Zip Direct Overwrite Engine**：支持直接从 GitHub 下载 `main.zip` 在内存中解压并覆盖更新应用代码文件，彻底解决 Docker 容器内部缺乏 Git 命令或 Docker Socket 导致的更新失败问题。
- **Beautified Cyber Modal Dialogs**：重构前发全站弹窗提示，全面替代浏览器原生 `alert()`，呈现纯正 VT100 暗黑终端与玻璃拟态视觉体验。
- **Smooth Container Auto-Reload**：热更新完成后自动触发守护进程平滑重启 (1.5s)，并在 3 秒内自动刷新页面加载新版本。

### 🟢 `v3.5.0` (2026-07-29) - Live Mini-Sparklines & Fullscreen Telemetry & SLA Hover Popovers
- **Live Canvas Mini-Sparklines**：在 CPU、Memory、Disk 与 Net Traffic (RX/TX) 监控项旁内嵌 Live Sparkline Canvas 动态走势线。
- **Fullscreen Telemetry Mode**：`$ tcping --watch` 新增 `[ ⛶ FULLSCREEN ]` 模式，一键展开全屏监控看板。
- **Interactive SLA Hover Popovers**：30-Day SLA 热力图方块全面支持赛博悬浮浮窗，丰富展现 SLA% / Max Latency / Incident count 数据。
- **Cyber Glassmorphism Polish**：优化玻璃拟态边框高亮与阴影 hover 动效，补全全站 Console UI 视觉层级。
- **TSDB Disk Persistence**：增加 `TimeSeriesDB` 磁盘快照自动持久化落盘与装载恢复，支持宿主机 `/opt/console-web/data` 卷持久挂载。
- **Standardized Node ID Structure**：重构 `get_auto_node_id()` 命名生成算法，消除重复 `-01-01` 后缀，输出标准简明 Node ID（如 `fra-hetzner-vps01` / `hkg-aliyun-vps01` / `de-vps01`）。
- **Host Persistence Deployment**：更新 `deploy.sh` 及 `docker-compose.yml` 挂载路径为宿主机 `/opt/console-web`。
- **Ultra-Smooth Cyber Curves**：升级 `$ tcping --watch` 为贝塞尔平滑折线图、双重 Neon 光晕 Pass、区域渐变填充及 Halo 节点数据点。
- **Interactive Hairline Crosshair & Tooltip**：新增 Canvas 悬浮垂直十字光标与浮窗 telemetry 节点数据展示。
- **Dynamic IP Geolocation Node ID**：根据服务器出口 IP 归属地与 ISP 自动生成真实 Node ID（如 `fra-hetzner-01` / `hkg-aliyun-01` / `sjc-leaseweb-01`）。
- **SemVer Comparison & GH Actions Lock**：主界面内置版本号徽章与 GitHub 直达连接；精确修复 SemVer 比较算法，对接 GitHub Actions Docker 镜像构建状态同步锁，完成自动编译后解锁一键热更新。

### 🟢 `v3.1.1` (2026-07-29) - 架构模块化重构 & Flask Blueprint 路由解耦
- **Package Modularization**：重构单文件结构，拆分为 `app/routes/` Flask Blueprints 独立路由层、`app/templates/` 单页 HTML 模板及核心解耦组件。
- **Engine Extraction**：提取 `tsdb.py` (内存时序引擎)、`system_stats.py` (硬件统计)、`diagnostics.py` (12阶段全链路诊断) 与 `ip_quality.py` (IP 质量分析)。
- **Route Blueprint Registration**：实现 `views`, `api`, `targets`, `diagnostics`, `acme`, `events` 模块化 Blueprint 路由注册与全兼容 API 别名。

### 🟢 `v3.1.0` (2026-07-29) - 内存时序数据库 & 像素柱状图 & 复古 CRT 终端重构
- **In-Memory TimeSeriesDB**：新增 `TimeSeriesDB` 内存时序引擎，支持滑动时间窗口存储与分标量统计（Cur, Avg, Min, Max, P95, P99, Jitter, Loss%）。
- **Cyber Pixel Bar Histogram**：将传统折线图升级为像素频谱柱状图 (Pixel Bar Histogram)，绘制离散 4px 堆叠块与 Peak 峰值标记。
- **Unified Single Identity Copy**：网络身份区合并为单一 `[ COPY ALL IDENTITIES ]` 按钮，一键导出完整网络身份元数据。
- **100% Pure English Localization**：界面所有标题、表头、按钮、模态框及日志消息全面英文化。
- **Retro CRT Monospace Styling**：强制全站 `Monospace` 字体，融入 CRT 扫描线显像管质感。

### 🟢 `v3.0.0` (2026-07-29) - 响应式多端重构与视觉交付
- **Visual Design System**：全站确立克制暗黑终端 UI，规范绿色（`#78E08F`）仅用于健康状态与主要操作，解决过去亮绿色过多、层级不清晰的问题。
- **Mobile Responsive Navbar**：桌面端顶部 Sticky 导航；移动端（<768px）新增 Fixed 底部导航栏与 44px+ 触控交互，顶部同步隐藏冗余信息。
- **Mobile Card Breakdown**：在移动端将 IPv4/IPv6 协议对比矩阵与网卡列表宽表格重构为 Mobile Card 上下堆叠组件，彻底消除手机横向滚动。
- **1-Click IP Copy & Toast**：新增 IP 旁一键复制按钮，适配非 HTTPS 降级模式，并提供 Toast 浮动平滑提示。
- **Multi-Target Latency Canvas**：重构 `$ tcping --watch` 趋势图，支持三大运营商 (联通/移动/电信) 及 Cloudflare/Google 多目标独立色彩折线与数据粒度（1m/5m/15m）选择。
- **Identity Accordion**：移动端 Hero 卡片新增身份与来源信息折叠抽屉，提升小屏显示效率。

### 🔵 `v2.5.0` (2026-07-20) - 全链路诊断与 SLA 热力图
- **12 阶段诊断引擎**：新增 `$ diagnose --full` 自动化链路排查任务流。
- **30-Day SLA Heatmap**：新增 `$ uptime --history --days=30` SLA 30 天块状交互热力图。
- **网络身份四分法**：明确划分 Server Listen、Server Egress、Visitor Client、Local Interface 来源。

### 🟣 `v2.0.0` (2026-06-15) - ACME SSL 自动化与主题切换
- **ACME IP/域名证书自动化**：内置 HTTP-01 Challenge 服务，支持向 ZeroSSL 申请公网 IP SSL 证书及静默自动续期。
- **三款赛博主题**：支持 Matrix Classic、Cyberpunk Neon、Tech Blue 无缝切换。

### 🟡 `v1.0.0` (2026-05-01) - 初始版本发布
- 基础 psutil 资源监控、Web Terminal 命令行交互与 SSE 流式日志回显。

---

## 🛠️ 本地开发与直接运行

```bash
pip install flask psutil

python app/main.py
```
应用默认监听在 `http://127.0.0.1:8180`。

---

## 🐳 Docker 部署方式

### 方式一：运行一键脚本
```bash
chmod +x deploy.sh
./deploy.sh
```

### 方式二：使用 Docker CLI 直接运行
```bash
docker run -d \
  --name console-web \
  --restart=always \
  -p 8180:8080 \
  -v ./certs:/app/certs \
  --memory=128m --memory-swap=128m \
  ghcr.io/podcctv/console-web:latest
```

### 方式三：使用 Docker Compose
```bash
docker compose up -d
```

默认将容器的 `8080` 端口映射到宿主机的 `8180` 端口，并将证书保存至挂载卷 `./certs`。

---

## 🤖 GitHub Actions 自动镜像生成

项目配置了自动化的 GitHub Actions 工作流（`.github/workflows/docker-publish.yml`）：
- **自动多架构构建**：每次提交合并至 `main` 分支或发布 Release Tag 时，GitHub Actions 会自动使用 Buildx 构建 `linux/amd64` 与 `linux/arm64`（适应 x86 服务器及 Oracle/甲骨文 ARM 云主机）镜像。
- **自动发布镜像**：自动推送到 GitHub Container Registry (GHCR)：`ghcr.io/podcctv/console-web:latest`。

---

## 📁 目录结构
```
.
├── app/                  # Flask 应用与 NetWatch 后端引擎
│   ├── main.py           # 应用入口启动与 Gunicorn / Flask 执行控制
│   ├── __init__.py       # Flask App 工厂、日志初始化与后台 Daemon 守护线程
│   ├── config.py         # 全局配置、版本号与默认 Ping 目标声明
│   ├── tsdb.py           # 内存时序数据库引擎 (TimeSeriesDB)
│   ├── system_stats.py   # psutil 系统资源与 SLA 统计逻辑
│   ├── diagnostics.py    # 12 阶段全链路网络诊断引擎
│   ├── ip_quality.py     # IP 地理位置与质量诊断模块
│   ├── network.py        # TCP/ICMP Ping 探测与 IP 探测辅助函数
│   ├── acme_manager.py   # ACME SSL 证书自动化与续期守护进程
│   ├── routes/           # Flask Blueprints 模块化路由层
│   │   ├── views.py      # 主 UI 模板渲染路由 (/)
│   │   ├── api.py        # 系统状态 (/stats)、Ping 测速与通用 API
│   │   ├── targets.py    # 监控目标 CRUD 管理 API (/api/targets)
│   │   ├── diagnostics.py # 网络诊断与双栈排查 API (/api/diagnose/*)
│   │   ├── acme.py       # ACME HTTP-01 Challenge 与证书管理 API
│   │   └── events.py     # 诊断报告导出 API (/api/report/export)
│   └── templates/        # 视图 UI 模板
│       └── index.html    # NetWatch 赛博终端前发单页 UI
├── certs/                # ACME 证书存储与 Challenge 目录
├── Dockerfile            # 多架构 Docker 构建配置
├── deploy.sh             # 一键自动部署脚本
├── docker-compose.yml    # Compose 一键编排文件
└── .github/workflows/    # GitHub Actions 自动化镜像生成工作流
```

## 📜 许可证
本项目采用 MIT 许可证开源。
