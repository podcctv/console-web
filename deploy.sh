#!/bin/sh

set -e

IMAGE_NAME="ghcr.io/podcctv/console-web:latest"
CONTAINER_NAME="console-web"
PORT=8180

check_env() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "⚙️  安装 Docker..."
    apk add --no-cache docker >/dev/null
    rc-update add docker boot >/dev/null
    service docker start >/dev/null
  fi
}

clean() {
  echo "🧹 正在清理旧容器和镜像..."
  docker stop "$CONTAINER_NAME" 2>/dev/null || true
  docker rm "$CONTAINER_NAME" 2>/dev/null || true
  docker rmi "$IMAGE_NAME" 2>/dev/null || true
  docker system prune -f 2>/dev/null || true
}

deploy() {
  clean
  echo "📥 拉取镜像：$IMAGE_NAME"
  docker pull "$IMAGE_NAME"

  echo "🚀 正在运行新容器..."
  docker run -d \
    --name "$CONTAINER_NAME" \
    -p ${PORT}:8080 \
    --memory=128m --memory-swap=128m \
    -e THEME=matrix \
    "$IMAGE_NAME"

  SERVER_IP=$(ip route get 1 | awk '{print $7; exit}')
  echo "✅ 部署完成！请访问：http://${SERVER_IP}:${PORT}"
}

delete() {
  clean
  echo "✅ 删除完成"
}

ACTION=$1
check_env

if [ -z "$ACTION" ]; then
  echo "请选择操作："
  echo "1) 重新部署系统"
  echo "2) 删除已运行的 Docker"
  printf "输入选项编号 (3 秒后默认选择 1): "
  read -t 3 choice || choice=1
  case "$choice" in
    1) ACTION=deploy ;;
    2) ACTION=delete ;;
    *) echo "❌ 无效选项"; exit 1 ;;
  esac
fi

case "$ACTION" in
  deploy) deploy ;;
  delete) delete ;;
  *) echo "用法: $0 [deploy|delete]"; exit 1 ;;
esac
