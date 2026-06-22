#!/bin/bash
# ============================================
# 服务器日志智能分析 —— 一键启动脚本 (Linux/Mac)
# 自动检测 Docker / Podman
# ============================================

echo "=========================================="
echo "  服务器日志智能分析系统"
echo "  Server Log Intelligent Analyzer"
echo "=========================================="
echo ""

# 检测容器运行时：优先 Docker，其次 Podman
CONTAINER_CMD=""
COMPOSE_CMD=""

if command -v docker &> /dev/null && docker info &> /dev/null; then
    CONTAINER_CMD="docker"
elif command -v podman &> /dev/null && podman info &> /dev/null; then
    CONTAINER_CMD="podman"
else
    echo "[ERROR] 未检测到 Docker 或 Podman，请先安装并启动容器运行时"
    exit 1
fi

# 检测 compose 命令
if [ "$CONTAINER_CMD" = "docker" ]; then
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    fi
else
    if command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
    else
        COMPOSE_CMD="podman compose"
    fi
fi

if [ -z "$COMPOSE_CMD" ]; then
    echo "[ERROR] 未找到 compose 工具"
    exit 1
fi

echo "[INFO] 检测到: $CONTAINER_CMD  +  $COMPOSE_CMD"
echo ""

# 启动容器
echo "[1/3] 启动容器环境..."
cd "$(dirname "$0")/docker"
$COMPOSE_CMD up -d
echo "[OK] 容器运行中"

# 等待容器就绪
echo "[2/3] 等待容器就绪..."
sleep 5

# 启动 Streamlit 界面
echo "[3/3] 启动 Streamlit 监控界面..."
cd "$(dirname "$0")/src"
streamlit run app.py
