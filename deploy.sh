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

  # Check if port 80 is free on host for ACME HTTP-01 challenge
  PORT80_MAPPED=0
  PORT_MAP="-p ${PORT}:8080"

  echo ""
  echo "🔍 检查宿主机 80 端口状态..."
  if netstat -tlpn 2>/dev/null | grep -q ":80 " || ss -tlpn 2>/dev/null | grep -q ":80 " || lsof -i:80 >/dev/null 2>&1; then
    echo "⚠️ 检测到宿主机 80 端口已被其他服务 (如 Nginx/Apache) 占用。"
    echo "   若需 ACME 自动签发证书，请配置 Web 反向代理将 /.well-known/acme-challenge/ 转发至 http://127.0.0.1:${PORT}"
    PORT_MAP="-p ${PORT}:8080"
  else
    echo "✅ 宿主机 80 端口空闲，自动绑定映射 -p 80:8080 供 ACME HTTP-01 验证。"
    PORT80_MAPPED=1
    PORT_MAP="-p 80:8080 -p ${PORT}:8080"
  fi

  echo ""
  echo "🚀 正在启动容器 [$CONTAINER_NAME]..."
  docker run -d \
    --name "$CONTAINER_NAME" \
    --restart=always \
    $PORT_MAP \
    -v console-web-certs:/app/certs \
    --memory=128m --memory-swap=128m \
    "$IMAGE_NAME"

  echo "⏳ 等待容器服务初始化 (3 秒)..."
  sleep 3

  # Port 80 reachability self-test
  echo ""
  echo "🔍 正在测试 80 端口 ACME 挑战可达性..."
  docker exec "$CONTAINER_NAME" sh -c "mkdir -p /app/certs/.well-known/acme-challenge && echo 'acme_port80_ok' > /app/certs/.well-known/acme-challenge/port80_test" 2>/dev/null || true

  TEST_RES=$(curl -s --max-time 4 "http://127.0.0.1:80/.well-known/acme-challenge/port80_test" 2>/dev/null || echo "")
  if [ "$TEST_RES" = "acme_port80_ok" ]; then
    echo "✅ 80 端口 HTTP-01 路由连通性校验成功！ACME CA 即可进行外网验证。"
  else
    echo "⚠️ 80 端口本地/外网校验未直通 (若 80 端口被防火墙拦截，ACME 可能会提示验证失败)。"
    echo "   💡 建议：请在云服务器控制台 (阿里云/腾讯云/AWS/华为云) 安全组入站规则中放行 80 端口。"
  fi
  docker exec "$CONTAINER_NAME" rm -f /app/certs/.well-known/acme-challenge/port80_test 2>/dev/null || true

  echo ""
  echo "🔒 正在执行 ACME SSL 官方证书检测与申请..."
  HAS_SSL=0
  if docker exec "$CONTAINER_NAME" python -m app.acme_manager; then
    HAS_SSL=1
    # 重启容器以使 Python 服务加载新签发的 SSL 证书 (若首次签发)
    docker restart "$CONTAINER_NAME" >/dev/null 2>&1 || true
    sleep 2
  fi

  SERVER_IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}' || curl -s ifconfig.me || echo "your-server-ip")
  echo ""
  echo "=================================================="
  echo "🎉 部署完成！Console-Web 已成功在后台运行。"
  if [ "$HAS_SSL" -eq 1 ]; then
    echo "🔒 ACME SSL 官方证书检测通过，已开启 HTTPS 安全加密访问。"
    echo "👉 HTTPS 访问地址: https://${SERVER_IP}:${PORT} (或 https://${SERVER_IP})"
    echo "👉 HTTP  备用地址: http://${SERVER_IP}:${PORT}"
  else
    echo "👉 访问地址: http://${SERVER_IP}:${PORT}"
    echo "💡 证书未签发成功提示：请确认 80 端口已在云服务器安全组中开放，然后在控制台终端运行 'acme issue' 即可重新申请！"
  fi
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
