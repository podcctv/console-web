# console-web (NetWatch 赛博朋克网络运维终端)

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-pub![Version](https://img.shields.io/badge/version-v3.1.0-78E08F?style=flat-square&logo=git)
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

> 💡 **部署说明**：脚本会自动检查并安装 Docker（如未安装），从 GHCR (`ghcr.io/podcctv/console-web:latest`) 拉取预构建镜像并在 `8180` 端口运行容器，部署成功后会直接输出提示与访问 URL。

---

## ✨ 核心功能

- **⚡ 内存时序数据库 (TimeSeriesDB v3.1 升级)**：
  - 内置 Python 线程安全内存时序数据库，采用固定容量（1440 points / 24h）滑动窗口滚动存贮，零磁盘 I/O 压力。
- **📊 赛博像素柱状图 (Pixel Bar Histogram v3.1 升级)**：
  - 弃用传统折线图，采用高科技复古像素柱状图 (Pixel Spectrum Analyzer) 渲染。离散 4px 块状堆叠（绿色 Healthy / 橙色 Warning / 红色 Alert）及顶部白色 Peak 峰值指示。
- **📋 统一一键 IP 复制 (`[ COPY ALL IDENTITIES ]`)**：
  - 网络身份区域提供单一顶部复制按钮，一键提取 Listen、Egress、Visitor 及 Local 接口的结构化文本至剪贴板。
- **🔤 纯正英文运维语言 & 老式 CRT 终端风格**：
  - 全站 100% 纯英文提示与标示，全站强制 `Monospace` 等宽字体与 CRT 扫描线背景，呈现纯正 VT100 终端体验。
- **📱 响应式多端适配**：
  - 顶部 Sticky 粘性导航 + 移动端（<768px）Fixed 触控导航栏与 Mobile Card 布局。

---

## 📅 版本更新日志 (Changelog)

📌 **版本号管理规范**：本项目遵从 [语义化版本 2.0.0 (Semantic Versioning)](https://semver.org/lang/zh-CN/) 规范（`MAJOR.MINOR.PATCH`）。每次更新同步修改 `app/main.py` (`__version__`)、`setup.cfg` (`version`) 及 `README.md`。

### 🟢 `v3.1.0` (2026-07-29) - 内存时序数据库 & 像素柱状图 & 复古 CRT 终端重构
- **In-Memory TimeSeriesDB**：新增 `TimeSeriesDB` 内存时序引擎，支持滑动时间窗口存储与分标量统计（Cur, Avg, Min, Max, P95, P99, Jitter, Loss%）。
- **Cyber Pixel Bar Histogram**：将传统折线图升级为像素频谱柱状图 (Pixel Bar Histogram)，绘制离散 4px 堆叠块与 Peak 峰值标记。
- **Unified Single Identity Copy**：网络身份区合并为单一 `[ COPY ALL IDENTITIES ]` 按钮，一键导出完整网络身份元数据。
- **100% Pure English Localization**：界面所有标题、表头、按钮、模态框及日志消息全面英文化。
- **Retro CRT Monospace Styling**：强制全站 `Monospace` 字体，融入 CRT 扫描线显像管质感。

### 🟢 `v3.0.0` (2026-07-29) - 响应式多端重构与视觉交付
- **Visual Design System**：全站确立暗黑终端 UI，规范绿色（`#78E08F`）仅用于健康状态与主要操作。
- **Mobile Responsive Navbar**：桌面端顶部 Sticky 导航；移动端（<768px）新增 Fixed 底部导航栏与 44px+ 触控交互。
- **Mobile Card Breakdown**：在移动端将协议对比矩阵与网卡列表宽表格重构为 Mobile Card 上下堆叠组件。��网 IP 地址或自定义域名自动向 ZeroSSL / Let's Encrypt 申请 90 天免费 SSL 证书。
  - 后台守护进程自动监测证书过期天数，**小于 30 天时自动触发静默自动续期**。
- **⚡ 12 阶段全链路网络诊断流**：
  - 支持 `$ diagnose --full` 自动排查 DNS 解析、TCP 连通性、MTU/MSS、TLS 握手及路由 Hop。
- **📊 30 天 SLA 可用率热力图**：
  - 支持 `$ uptime --history --days=30` 记录与交互式悬浮显示历史中断与故障分析。

---

## 📅 版本更新日志 (Changelog)

📌 **版本号管理规范**：本项目遵从 [语义化版本 2.0.0 (Semantic Versioning)](https://semver.org/lang/zh-CN/) 规范（`MAJOR.MINOR.PATCH`）。每次更新同步修改 `app/main.py` (`__version__`)、`setup.cfg` (`version`) 及 `README.md`。

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
├── app/                  # Flask 应用、系统监控与 ACME 证书管理模块
│   ├── main.py           # 核心应用入口与 NetWatch 单页 UI 模板
│   ├── acme_manager.py   # ACME SSL 证书管理与自动续期守护进程
│   └── ip_quality.py     # IP 质量与地理位置诊断模块
├── certs/                # ACME 证书存储与 Challenge 目录
├── Dockerfile            # 多架构 Docker 构建配置
├── deploy.sh             # 一键自动部署脚本
├── docker-compose.yml    # Compose 一键编排文件
└── .github/workflows/    # GitHub Actions 自动化镜像生成工作流
```

## 📜 许可证
本项目采用 MIT 许可证开源。
