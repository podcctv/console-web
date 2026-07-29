# console-web (NetWatch 赛博朋克网络运维终端)

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-publish.yml/badge.svg)
![Version](https://img.shields.io/badge/version-v3.6.1-78E08F?style=flat-square&logo=git)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

`console-web` 是一个基于 [Flask](https://flask.palletsprojects.com/) 和 [psutil](https://psutil.readthedocs.io/) 构建的极简赛博朋克风格系统监控面板与网络运维终端 (`NetWatch`)。界面采用暗黑终端与玻璃拟态设计，支持实时 TCP Ping 多目标延迟趋势、IPv4/IPv6 双栈链路对比、多端响应式适配、1-Click IP 复制、ACME SSL 证书自动续期及全链路故障诊断。

<img width="1012" height="1054" alt="image" src="https://github.com/user-attachments/assets/5093b202-5b38-4929-ac9a-1db5062d863a" />

---

## 🚀 一键快速部署 (推荐)

在 Linux 服务器（Ubuntu、Debian、CentOS、Alpine 等）上直接运行以下指令，即可一键自动安装 Docker 并完成镜像部署：

```bash
curl -fsSL https://raw.githubusercontent.com/podcctv/console-web/main/deploy.sh | sh
```

或者使用 `wget` 执行：

```bash
wget -qO- https://raw.githubusercontent.com/podcctv/console-web/main/deploy.sh | sh
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

---

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
