@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM ============================================
REM Server Log Intelligent Analyzer - Launcher
REM Auto-detect Docker Desktop / Podman
REM ============================================

echo ==========================================
echo   Server Log Intelligent Analyzer
echo ==========================================
echo.

REM Detect container runtime: prefer Docker, fallback to Podman
set CONTAINER_CMD=
set COMPOSE_CMD=

REM Check Docker
docker info >nul 2>&1
if !errorlevel! equ 0 (
    set CONTAINER_CMD=docker
    goto :check_compose
)

REM Check Podman
podman info >nul 2>&1
if !errorlevel! equ 0 (
    set CONTAINER_CMD=podman
    goto :check_compose
)

echo [ERROR] Neither Docker nor Podman found. Please install and start a container runtime.
pause
exit /b 1

:check_compose
REM Detect compose command
if "!CONTAINER_CMD!"=="docker" (
    docker compose version >nul 2>&1
    if !errorlevel! equ 0 (
        set "COMPOSE_CMD=docker compose"
        goto :compose_done
    )
    docker-compose --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "COMPOSE_CMD=docker-compose"
        goto :compose_done
    )
) else (
    podman-compose --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "COMPOSE_CMD=podman-compose"
        goto :compose_done
    )
    set "COMPOSE_CMD=podman compose"
)

:compose_done
if "!COMPOSE_CMD!"=="" (
    echo [ERROR] No compose tool found. Please install docker-compose or podman-compose.
    pause
    exit /b 1
)

echo [INFO] Detected: !CONTAINER_CMD! + !COMPOSE_CMD!
echo.

REM Start containers
echo [1/4] Starting container environment...
cd /d "%~dp0docker"
!COMPOSE_CMD! up -d
if !errorlevel! neq 0 (
    echo [ERROR] Container startup failed. Please check if !CONTAINER_CMD! is running.
    pause
    exit /b 1
)
echo [OK] Containers running

REM Wait for containers to be ready
echo [2/4] Waiting for containers to be ready...
timeout /t 5 /nobreak >nul

REM Activate venv (run setup.bat first if missing)
echo [3/4] Activating Python virtual environment...
if not exist "%~dp0venv\Scripts\activate.bat" (
    echo [ERROR] venv not found. Please run setup.bat first.
    pause
    exit /b 1
)
call "%~dp0venv\Scripts\activate.bat"
echo [OK] venv activated

REM Start Streamlit dashboard
echo [4/4] Starting Streamlit dashboard...
cd /d "%~dp0src"
start http://localhost:8501
streamlit run app.py

pause
