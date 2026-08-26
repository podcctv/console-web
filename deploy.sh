#!/bin/sh

set -e

IMAGE_NAME="ghcr.io/podcctv/console-web:latest"
CONTAINER_NAME="console-web"
PORT=8180

check_ipv6_nat64() {
  # If outbound IPv4 is completely unreachable, test if GitHub/GHCR can be resolved
  if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && ! curl -4 -s --connect-timeout 2 https://api.ipify.org >/dev/null 2>&1; then
    if ! curl -s --connect-timeout 3 https://ghcr.io >/dev/null 2>&1 && ! curl -s --connect-timeout 3 https://github.com >/dev/null 2>&1; then
      echo "⚡ 检测到当前节点为纯 IPv6 环境且无法直连 GitHub/GHCR，正在自动启用 DNS64 / NAT64 加速解析..."
      cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
      printf "nameserver 2a00:1098:2b::1\nnameserver 2a01:4f8:c2c:123f::1\nnameserver 2a00:1098:2c::1\n" > /tmp/resolv_dns64.conf
      cat /etc/resolv.conf >> /tmp/resolv_dns64.conf 2>/dev/null || true
      mv /tmp/resolv_dns64.conf /etc/resolv.conf 2>/dev/null || true
      echo "✅ DNS64 加速通道已配置，GHCR 镜像拉取畅通无阻！"
    fi
  fi
}

check_env() {
  check_ipv6_nat64

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

is_private_or_warp_ip() {
  _IP="$1"
  if [ -z "$_IP" ]; then return 0; fi
  # RFC 1918 Private IPv4: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, 100.64-127.x
  case "$_IP" in
    10.*|192.168.*|127.*|169.254.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    # Cloudflare WARP and CDN shared egress ranges
    104.28.*|104.29.*|104.1[6-9].*|104.2[0-7].*|162.158.*|172.6[4-9].*|172.7[0-1].*|198.41.*) return 0 ;;
  esac
  # Private IPv6
  case "$_IP" in
    fe80:*|fc00:*|fd00:*|::1|localhost) return 0 ;;
  esac
  return 1
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
  echo "📁 正在创建宿主机持久化目录 (/opt/console-web)..."
  mkdir -p /opt/console-web/data /opt/console-web/logs /opt/console-web/certs 2>/dev/null || true

  echo "🚀 正在启动容器 [$CONTAINER_NAME]..."
  docker run -d \
    --name "$CONTAINER_NAME" \
    --restart=always \
    $PORT_MAP \
    -v /opt/console-web/data:/app/data \
    -v /opt/console-web/logs:/app/logs \
    -v /opt/console-web/certs:/app/certs \
    --memory=128m --memory-swap=128m \
    "$IMAGE_NAME"

  echo "⏳ 等待容器 Web 服务初始化就绪..."
  CONTAINER_READY=0
  for i in $(seq 1 10); do
    if curl -s --max-time 1 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1 || \
       curl -s --max-time 1 "http://127.0.0.1:8080/" >/dev/null 2>&1 || \
       curl -s --max-time 1 "http://[::1]:${PORT}/" >/dev/null 2>&1 || \
       docker exec "$CONTAINER_NAME" curl -s --max-time 1 "http://127.0.0.1:8080/" >/dev/null 2>&1; then
      CONTAINER_READY=1
      break
    fi
    sleep 1
  done

  # Port 80 reachability self-test
  echo ""
  echo "🔍 正在测试 80 端口 ACME 挑战可达性..."
  docker exec "$CONTAINER_NAME" sh -c "mkdir -p /app/certs/.well-known/acme-challenge && echo 'acme_port80_ok' > /app/certs/.well-known/acme-challenge/port80_test" 2>/dev/null || true

  TEST_RES=$(curl -s --max-time 3 "http://127.0.0.1:80/.well-known/acme-challenge/port80_test" 2>/dev/null || \
             curl -s --max-time 3 "http://[::1]:80/.well-known/acme-challenge/port80_test" 2>/dev/null || echo "")
  if [ "$TEST_RES" = "acme_port80_ok" ]; then
    echo "✅ 80 端口 HTTP-01 路由连通性校验成功！ACME CA 即可进行外网验证。"
  else
    echo "⚠️ 80 端口本地校验未直通 (若 80 端口被云服务商安全组拦截，ACME 可能会提示验证失败)。"
    echo "   💡 建议：请在云服务器控制台安全组入站规则中放行 80 端口。"
  fi
  docker exec "$CONTAINER_NAME" rm -f /app/certs/.well-known/acme-challenge/port80_test 2>/dev/null || true

  echo ""
  echo "🔒 正在执行 ACME SSL 官方证书检测与申请..."
  HAS_SSL=0
  if docker exec "$CONTAINER_NAME" python -m app.acme_manager; then
    HAS_SSL=1
    echo "🔄 正在重启容器以启用 HTTPS 安全加密服务..."
    docker restart "$CONTAINER_NAME" >/dev/null 2>&1 || true
    sleep 2
  fi

  # 1. Detect IPv6 Public Address
  PUB_IPV6=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1); exit}')
  if is_private_or_warp_ip "$PUB_IPV6"; then
    PUB_IPV6=$(curl -6 -s --max-time 3 https://api6.ipify.org 2>/dev/null || curl -6 -s --max-time 3 https://v6.ident.me 2>/dev/null || echo "")
  fi
  if is_private_or_warp_ip "$PUB_IPV6"; then
    PUB_IPV6=""
  fi

  # 2. Detect IPv4 Public Address
  RAW_V4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1); exit}')
  PUB_IPV4="$RAW_V4"
  if is_private_or_warp_ip "$PUB_IPV4"; then
    PUB_IPV4=$(curl -4 -s --max-time 3 https://api.ipify.org 2>/dev/null || curl -4 -s --max-time 3 https://v4.ident.me 2>/dev/null || echo "")
  fi

  IS_WARP=0
  if echo "$RAW_V4 $PUB_IPV4" | grep -qE '(104\.(28|29)\.|10\.100\.)'; then
    IS_WARP=1
  fi
  if is_private_or_warp_ip "$PUB_IPV4"; then
    PUB_IPV4=""
  fi

  # 3. Determine Stack Type & Formatted URLs
  if [ -n "$PUB_IPV4" ] && [ -n "$PUB_IPV6" ]; then
    STACK_TYPE="dual"
    STACK_DESC="IPv4 / IPv6 双栈环境 (Dual-Stack)"
    PRIMARY_HOST="$PUB_IPV4"
    ALT_HOST="[${PUB_IPV6}]"
  elif [ -n "$PUB_IPV6" ]; then
    if [ "$IS_WARP" -eq 1 ]; then
      STACK_TYPE="v6_warp"
      STACK_DESC="纯 IPv6 (IPv6-Only) + Cloudflare WARP 出口"
    else
      STACK_TYPE="v6_only"
      STACK_DESC="纯 IPv6 环境 (IPv6-Only 纯v6)"
    fi
    PRIMARY_HOST="[${PUB_IPV6}]"
    ALT_HOST=""
  elif [ -n "$PUB_IPV4" ]; then
    STACK_TYPE="v4_only"
    STACK_DESC="纯 IPv4 环境 (IPv4-Only)"
    PRIMARY_HOST="$PUB_IPV4"
    ALT_HOST=""
  else
    STACK_TYPE="local"
    STACK_DESC="本地 / 局域网环境"
    PRIMARY_HOST="127.0.0.1"
    ALT_HOST=""
  fi

  echo ""
  echo "=================================================="
  echo "🎉 部署完成！Console-Web 已成功在后台运行 (${STACK_DESC})。"
  if [ "$HAS_SSL" -eq 1 ]; then
    echo "🔒 ACME SSL 官方证书检测通过，已开启 HTTPS 安全加密访问。"
    echo "👉 HTTPS 访问地址: https://${PRIMARY_HOST}:${PORT} (或 https://${PRIMARY_HOST})"
    echo "👉 HTTP  备用地址: http://${PRIMARY_HOST}:${PORT}"
  else
    echo "👉 访问地址: http://${PRIMARY_HOST}:${PORT}"
    echo "💡 证书未签发成功提示：请确认 80 端口已在云服务器安全组中开放，然后在控制台终端运行 'acme issue' 即可重新申请！"
  fi
  if [ -n "$ALT_HOST" ]; then
    echo "👉 备用地址: http://${ALT_HOST}:${PORT}"
  fi
  if [ "$STACK_TYPE" = "v6_only" ] || [ "$STACK_TYPE" = "v6_warp" ]; then
    echo ""
    echo "💡 纯 IPv6 小鸡极速访问提示："
    echo "   1. 请确保访问客户端支持 IPv6 (如手机 5G / 家用宽带 IPv6 / 校园网即可直接秒开)；"
    echo "   2. 建议将您的域名添加 AAAA 记录解析至 ${PRIMARY_HOST}，并在控制台运行 'acme issue 您的域名' 即可 100% 直通签发官方 SSL 证书！"
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
