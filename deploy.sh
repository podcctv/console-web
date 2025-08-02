#!/bin/bash

set -e

REPO_URL="https://github.com/podcctv/console-web.git"
CLONE_DIR="console-web"
IMAGE_NAME="console-web"
PORT=8180

clean() {
  echo "🧹 正在清理旧容器和镜像..."
  docker stop "$IMAGE_NAME" 2>/dev/null || true
  docker rm "$IMAGE_NAME" 2>/dev/null || true
  docker rmi "$IMAGE_NAME" 2>/dev/null || true
}

deploy() {
  clean
  echo "📥 正在克隆仓库：$REPO_URL"
  rm -rf "$CLONE_DIR"
  git clone "$REPO_URL" "$CLONE_DIR"

  echo "🐳 正在构建 Docker 镜像：$IMAGE_NAME"
  docker build --no-cache -t "$IMAGE_NAME" "$CLONE_DIR"

  echo "🚀 正在运行新容器..."
  docker run -d \
    --name "$IMAGE_NAME" \
    -p ${PORT}:8080 \
    -e CUSTOM_MSG="来自 Flanker 的神秘终端" \
    -e THEME=matrix \
    "$IMAGE_NAME"

  echo "✅ 部署完成！请访问：http://<服务器IP>:${PORT}"
}

delete() {
  clean
  echo "✅ 删除完成"
}

ACTION=$1

if [ -z "$ACTION" ]; then
  echo "请选择操作："
  echo "1) 重新部署系统"
  echo "2) 删除已运行的 Docker"
  read -p "输入选项编号: " choice
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
