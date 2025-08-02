#!/bin/bash

set -e

# 自动识别版本号和压缩包
ARCHIVE_NAME=$(ls console-web-*-enhanced.tar.gz | head -n 1)

if [ ! -f "$ARCHIVE_NAME" ]; then
  echo "❌ 找不到压缩包：console-web-*-enhanced.tar.gz"
  exit 1
fi

APP_NAME=$(basename "$ARCHIVE_NAME" .tar.gz)
IMAGE_NAME="${APP_NAME//-enhanced/}"
PORT=8180
CONTEXT_DIR="${APP_NAME}"

echo "🧹 正在清理旧容器和镜像..."
docker stop "$IMAGE_NAME" 2>/dev/null || true
docker rm "$IMAGE_NAME" 2>/dev/null || true
docker rmi "$IMAGE_NAME" 2>/dev/null || true

echo "📦 正在解压安装包：$ARCHIVE_NAME"
rm -rf "$CONTEXT_DIR"
tar -xzf "$ARCHIVE_NAME"

echo "🐳 正在构建 Docker 镜像：$IMAGE_NAME"
cd "$CONTEXT_DIR"
docker build --no-cache -t "$IMAGE_NAME" .

echo "🚀 正在运行新容器..."
docker run -d \
  --name "$IMAGE_NAME" \
  -p ${PORT}:8080 \
  -e CUSTOM_MSG="来自 Flanker 的神秘终端" \
  -e THEME=matrix \
  "$IMAGE_NAME"

echo "✅ 部署完成！请访问：http://<服务器IP>:${PORT}"
