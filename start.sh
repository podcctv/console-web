#!/bin/sh
set -e

# Determine repository root and ensure consistent working directory
ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN=${PYTHON:-python3}
INSTALL_DEPS=0
USE_GUNICORN=0

usage() {
  cat <<'USAGE'
用法: ./start.sh [选项]

选项:
  --install-deps   首次运行时安装依赖 (pip install -r requirements.txt)
  --gunicorn       使用 gunicorn 以生产模式启动 (默认端口 8080)
  -h, --help       查看此帮助

可以通过环境变量 PYTHON 指定 Python 解释器，例如:
  PYTHON=python3.12 ./start.sh --install-deps
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-deps)
      INSTALL_DEPS=1
      ;;
    --gunicorn)
      USE_GUNICORN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "未找到 Python，可通过设置 PYTHON 指定解释器" >&2
  exit 1
fi

if [ "$INSTALL_DEPS" -eq 1 ]; then
  echo "📦 正在安装依赖..."
  "$PYTHON_BIN" -m pip install --no-cache-dir -r requirements.txt
fi

export PYTHONPATH="$ROOT_DIR:$PYTHONPATH"

if [ "$USE_GUNICORN" -eq 1 ]; then
  echo "🚀 使用 gunicorn 启动 (监听 0.0.0.0:8080)..."
  exec "$PYTHON_BIN" -m gunicorn -b 0.0.0.0:8080 main:app
else
  echo "🚀 使用内置服务器启动 (监听 0.0.0.0:8080)..."
  exec "$PYTHON_BIN" main.py
fi
