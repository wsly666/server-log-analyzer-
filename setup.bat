@echo off
chcp 65001 >nul 2>&1
setlocal

echo ==========================================
echo   AI-OPS 环境初始化
echo ==========================================
echo.

REM ── 1. 检查 Python ──
echo [1/3] 检查 Python...
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] 未找到 Python，请先安装 Python 3.10+
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo [OK] Python %%v

REM ── 2. 创建虚拟环境 ──
echo.
echo [2/3] 创建虚拟环境...
if exist "%~dp0venv" (
    echo [SKIP] venv 已存在，跳过
) else (
    python -m venv "%~dp0venv"
    if !errorlevel! neq 0 (
        echo [ERROR] 创建 venv 失败
        pause
        exit /b 1
    )
    echo [OK] venv 创建完成
)

REM ── 3. 安装依赖 ──
echo.
echo [3/3] 安装 Python 依赖...
call "%~dp0venv\Scripts\activate.bat"
pip install -r "%~dp0requirements.txt" -q
if !errorlevel! neq 0 (
    echo [ERROR] 依赖安装失败，请检查网络连接
    pause
    exit /b 1
)
echo [OK] 依赖安装完成

REM ── 检查 .env ──
echo.
if not exist "%~dp0.env" (
    echo [WARN] 未找到 .env 文件，复制模板...
    copy "%~dp0.env.example" "%~dp0.env" >nul
    echo [TODO] 请编辑 .env 填入你的 DeepSeek API Key 和邮箱配置
) else (
    echo [INFO] .env 已存在，跳过
)

echo.
echo ==========================================
echo   初始化完成！
echo   如需配置 API Key，请编辑 .env 文件
echo   然后运行 run.bat 启动项目
echo ==========================================
pause
