# console-web

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-publish.yml/badge.svg)

`console-web` 是一个基于 [Flask](https://flask.palletsprojects.com/) 和 [psutil](https://psutil.readthedocs.io/) 构建的极简赛博朋克风格系统监控面板与网络诊断工具。界面采用暗黑终端与玻璃拟态设计，实时展示 CPU、内存、磁盘、网络 IO 及各运营商延迟状态。

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
- **赛博极客风格界面**：支持 `Matrix Classic` 绿、`Cyberpunk Neon` 紫、`Tech Blue` 蓝三款主题一键无缝切换。
- **实时系统性能监控**：CPU 使用率、内存、磁盘空间平滑渐变进度条，带智能使用率预警。
- **网络流量与 IO**：实时显示当前上传/下载速率、磁盘读写速度、公网/内网 IP 以及客户端 IP & ISP 运营商。
- **动态 Latency 折线图**：对三大运营商（联通、移动、电信）及本地客户端的 TCP/ICMP Ping 进行可视化高帧率 Canvas 折线图绘制。
- **图形化域名/IP 快速诊断**：支持直接输入任意 URL / IP 查询 DNS 解析、地理位置/ISP 运营商及响应延迟。
- **增强型 Web Terminal**：
  - 支持**键盘上下方向键（Up/Down Arrow）**调出历史命令。
  - 内置一键快捷动作按钮（`Ping 联通`、`Ping 移动`、`MTR 1.1.1.1`、`清屏` 等）。
  - 支持 `ping`、`mtr`、`lookup`、`stats`、`theme` 等命令的实时 SSE 流式回显。

---

## 🛠️ 本地开发与直接运行

```bash
pip install flask psutil

python app/main.py
```
应用默认监听在 `http://127.0.0.1:8080`。

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
  --memory=128m --memory-swap=128m \
  ghcr.io/podcctv/console-web:latest
```

### 方式三：使用 Docker Compose
```bash
docker compose up -d
```

默认将容器的 `8080` 端口映射到宿主机的 `8180` 端口。

---

## 🤖 GitHub Actions 自动镜像生成

项目配置了自动化的 GitHub Actions 工作流（`.github/workflows/docker-publish.yml`）：
- **自动多架构构建**：每次提交合并至 `main` 分支或发布 Release Tag 时，GitHub Actions 会自动使用 Buildx 构建 `linux/amd64` 与 `linux/arm64`（适应 x86 服务器及 Oracle/甲骨文 ARM 云主机）镜像。
- **自动发布镜像**：自动推送到 GitHub Container Registry (GHCR)：`ghcr.io/podcctv/console-web:latest`。

---

## 目录结构
```
.
├── app/                  # Flask 应用与 Web 前端模板
├── Dockerfile            # 多架构 Docker 构建配置
├── deploy.sh             # 一键自动部署脚本
├── docker-compose.yml    # Compose 一键编排文件
└── .github/workflows/    # GitHub Actions 自动化镜像生成工作流
```

## 许可证
本项目未声明许可证，默认保留所有权利。
