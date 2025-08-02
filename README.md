# console-web

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-publish.yml/badge.svg)

console-web 是一个使用 [Flask](https://flask.palletsprojects.com/) 和 [psutil](https://psutil.readthedocs.io/) 构建的极简系统状态面板，界面采用终端风格，实时展示 CPU、内存、磁盘、网络等信息。

## 功能
- 黑客风格的单页界面
- 实时显示 CPU、内存、磁盘使用率
- 容器与宿主机运行时间
- 本地/公网 IP、磁盘 IO、网络 IO 以及实时上传/下载速度
- 对多家运营商的 TCP Ping 监测
- 内置网络工具：Ping、MTR、SpeedTest，支持实时回显

## 本地运行
```bash
pip install flask psutil
# 安装官方 Speedtest CLI（下载并解压官方提供的压缩包）：https://www.speedtest.net/apps/cli
python app/main.py
```
应用默认监听在 `http://127.0.0.1:8080`。页面中提供 Ping、MTR、SpeedTest 按钮，可实时查看执行结果。

## Docker 部署
可以直接构建镜像：
```bash
docker build -t console-web .
docker run -d -p 8080:8080 console-web
```
或者使用仓库自带的脚本：
```bash
chmod +x deploy.sh
./deploy.sh
```
脚本会自动克隆仓库、构建镜像并在 8180 端口运行容器。运行时如未输入指令，将在 3 秒倒计时后默认重新部署，部署完成后会自动显示可访问的服务器 IP。

镜像内已预装 `iputils-ping`、`mtr` 和 官方 `speedtest` CLI（通过官方压缩包安装），因此 Web 终端提供的网络诊断命令可开箱即用。

## 目录结构
```
.
├── app/           # Flask 应用代码
├── Dockerfile     # 构建容器镜像
├── deploy.sh      # 部署脚本
└── .github/       # GitHub Actions 配置
```

## 许可证
本项目未声明许可证，默认保留所有权利。
