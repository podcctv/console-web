# console-web

![Build & Publish Docker](https://github.com/podcctv/console-web/actions/workflows/docker-publish.yml/badge.svg)

console-web 是一个使用 [Flask](https://flask.palletsprojects.com/) 和 [psutil](https://psutil.readthedocs.io/) 构建的极简系统状态面板，界面采用终端风格，实时展示 CPU、内存、磁盘、网络等信息。

<img width="1012" height="1054" alt="image" src="https://github.com/user-attachments/assets/5093b202-5b38-4929-ac9a-1db5062d863a" />


## 功能
- 黑客风格的单页界面
- 实时显示 CPU、内存、磁盘使用率
- 容器与宿主机运行时间
- 本地/公网 IP、磁盘 IO、网络 IO 以及实时上传/下载速度
- 对多家运营商的 TCP Ping 监测
- 查询任意 URL 的 IP、ISP 及 Ping 信息
- 内置网络工具：Ping、MTR，支持实时回显

## 本地运行
```bash
pip install flask psutil

python app/main.py
```
应用默认监听在 `http://127.0.0.1:8080`。页面中提供 Ping、MTR 按钮，可实时查看执行结果。

## Alpine 系统部署
在 Alpine Linux 中可以直接通过以下命令部署并运行：

```bash
# 安装运行及编译依赖
apk add --no-cache \
  python3 py3-pip git iputils mtr \
  build-base python3-dev linux-headers

git clone https://github.com/podcctv/console-web.git /opt/console-web
cd /opt/console-web

# 安装 Python 依赖并启动服务
pip install --break-system-packages -r requirements.txt
python app/main.py
```

### 添加服务
如需开机自启，可创建 OpenRC 服务：

```bash
cat <<'EOF' >/etc/init.d/console-web
#!/sbin/openrc-run
command="/usr/bin/python3 /opt/console-web/app/main.py"
command_background="yes"
pidfile="/run/console-web.pid"
depend() {
    need net
}
EOF
chmod +x /etc/init.d/console-web
rc-update add console-web default
service console-web start
```

### 卸载服务与程序
```bash
service console-web stop
rc-update del console-web default
rm /etc/init.d/console-web
rm -rf /opt/console-web
apk del python3 py3-pip git iputils mtr
```

## Docker 部署
可以直接构建镜像：
```bash
docker build -t console-web .
docker run -d -p 8180:8080 console-web
```
或者使用仓库自带的脚本：
```bash
chmod +x console-web/deploy.sh   # 赋予执行权限
./console-web/deploy.sh          # 执行脚本
```
<img width="1215" height="703" alt="image" src="https://github.com/user-attachments/assets/c73ec314-2feb-4064-a5e5-d27f3617d77f" />

脚本会自动安装 Docker（如未安装）、拉取预构建镜像并在 8180 端口运行容器，默认限制容器内存为 128MB。运行时如未输入指令，将在 3 秒后默认重新部署，部署完成后会自动显示可访问的服务器 IP。


镜像内已预装 `iputils-ping`、`mtr`，因此 Web 终端提供的网络诊断命令可开箱即用。

### Pella 面板启动指引

在 Pella 等面板启动容器时，避免出现 `Cannot find module '/app'` 的 Node 报错，可按以下配置填写：

- **工作目录（Working Directory）**：`/workspace/console-web`（或镜像内代码所在目录）。
- **命令（Command）**：`python`
- **主文件（Main file / App Entry）**：`app/main.py`
- **端口映射**：容器 `8080` 暴露到宿主机所需端口，例如 `8180:8080`。

入口脚本 `app/main.py` 已直接调用 `app.run(host="0.0.0.0", port=8080)` 启动 Flask 服务，指定 Python 解释器与入口文件即可正常运行。若运行环境默认使用 WSGI/Gunicorn 启动，可直接指定 `main:app` 作为入口（项目根目录提供了同名的转发脚本，避免在子目录下找不到模块）。

### Gunicorn 部署建议

部分 PaaS/容器环境在启动 Gunicorn 时不会自动把当前项目目录加入 `PYTHONPATH`，导致出现 `ModuleNotFoundError: No module named 'main'` 报错。可以先在代码目录执行一次可编辑安装，确保 `main` 模块被正确注册：

```bash
pip install -e .
gunicorn -b 0.0.0.0:8080 main:app
```

`requirements.txt` 已内置 `-e .` 与 `gunicorn`，可以直接执行：

```bash
pip install -r requirements.txt
gunicorn -b 0.0.0.0:8080 main:app
```

如果面板或启动器把入口写成带斜杠的 `app/main`，安装依赖后也可以正常启动——仓库提供的 `sitecustomize` 会在 Python 启动时把该“错误”模块名映射到正确的 `app.main`，避免 `ModuleNotFoundError: No module named 'app/main'` 的问题。

可编辑安装会将项目根目录添加到环境中，无论 Gunicorn 的工作目录在哪里，都能正确找到 `main:app`。


## Docker Compose 部署
仓库提供了 `docker-compose.yml` 示例，可以直接使用：

```bash
docker compose up -d
```

默认将容器的 `8080` 端口映射到宿主机的 `8080` 端口，并在后台运行。

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
