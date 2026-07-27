#!/bin/sh

set -e

IMAGE_NAME="ghcr.io/podcctv/console-web:latest"
CONTAINER_NAME="console-web"
PORT=8180

check_env() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "⚙️  未检测到 Docker，正在自动安装..."
    if command -v apk >/dev/null 2>&1; then
      apk add --no-cache docker >/dev/null
      rc-update add docker boot >/dev/null
      service docker start >/dev/null
    elif command -v curl >/dev/null 2>&1; then
      curl -fsSL https://get.docker.com | sh
    elif command -v wget >/dev/null 2>&1; then
      wget -qO- https://get.docker.com | sh
    else
      echo "❌ 无法自动安装 Docker，请手动安装 Docker 后重试。"
      exit 1
    fi
  fi
}

clean() {
  echo "🧹 正在清理旧容器与镜像..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  docker rm "$CONTAINER_NAME" 2>/dev/null || true
  docker rmi "$IMAGE_NAME" 2>/dev/null || true
  docker system prune -f 2>/dev/null || true
}

deploy() {
  clean
  echo "📥 正在从 GHCR 拉取最新镜像：$IMAGE_NAME"
  docker pull "$IMAGE_NAME"

  echo "🚀 正在启动容器 [$CONTAINER_NAME]..."
  docker run -d \
    --name "$CONTAINER_NAME" \
    --restart=always \
    -p ${PORT}:8080 \
    --memory=128m --memory-swap=128m \
    "$IMAGE_NAME"

  SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' || curl -s ifconfig.me || echo "your-server-ip")
  echo ""
  echo "=================================================="
  echo "🎉 部署完成！Console-Web 已成功在后台运行。"
  echo "👉 访问地址: http://${SERVER_IP}:${PORT}"
  echo "=================================================="
}

delete() {
  clean
  echo "✅ 已成功停止并删除 Console-Web 容器。"
}

ACTION=$1
check_env

if [ -z "$ACTION" ]; then
  if [ -t 0 ]; then
    echo "请选择操作："
    echo "1) 部署 / 重新部署 Console-Web"
    echo "2) 删除已运行的 Console-Web 容器"
    printf "输入选项编号 (5 秒后默认部署): "
    read -t 5 choice || choice=1
    case "$choice" in
      1) ACTION=deploy ;;
      2) ACTION=delete ;;
      *) echo "❌ 无效选项"; exit 1 ;;
    esac
  else
    ACTION=deploy
  fi
fi

case "$ACTION" in
  deploy) deploy ;;
  delete) delete ;;
  *) echo "用法: $0 [deploy|delete]"; exit 1 ;;
esac
