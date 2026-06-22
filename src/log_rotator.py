"""
日志轮转模块
自动检测日志文件大小，超过阈值时触发轮转（重命名 + 通知 nginx reopen）
"""

import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.config import LOG_PATHS, ROTATED_DIR, LOG_MAX_SIZE_MB, LOG_ROTATE_KEEP


def get_log_size_mb(log_key: str = "nginx_access") -> float:
    """获取日志文件大小 (MB)，文件不存在返回 0"""
    log_path = LOG_PATHS.get(log_key)
    if not log_path or not log_path.exists():
        return 0.0
    return log_path.stat().st_size / (1024 * 1024)


def _signal_nginx_reopen() -> bool:
    """通知 nginx 重新打开日志文件"""
    import subprocess
    try:
        result = subprocess.run(
            ["podman", "exec", "log-analyzer-nginx", "nginx", "-s", "reopen"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            # 尝试 docker
            result = subprocess.run(
                ["docker", "exec", "log-analyzer-nginx", "nginx", "-s", "reopen"],
                capture_output=True, text=True, timeout=10,
            )
        return result.returncode == 0
    except Exception as e:
        print(f"[LogRotator] nginx reopen 失败: {e}")
        return False


def rotate_log(log_key: str = "nginx_access", max_size_mb: int = None,
               keep: int = None) -> Optional[Path]:
    """
    轮转日志文件：将当前日志重命名为带时间戳的归档文件，创建新的空日志，通知 nginx reopen。

    返回归档文件路径，如果不需要轮转则返回 None。
    """
    if max_size_mb is None:
        max_size_mb = LOG_MAX_SIZE_MB
    if keep is None:
        keep = LOG_ROTATE_KEEP

    log_path = LOG_PATHS.get(log_key)
    if not log_path or not log_path.exists():
        return None

    size_mb = log_path.stat().st_size / (1024 * 1024)
    if size_mb < max_size_mb:
        return None

    # 确保归档目录存在
    ROTATED_DIR.mkdir(parents=True, exist_ok=True)

    # 生成归档文件名: access.20260622_114500.log
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_name = log_path.stem  # e.g. "access"
    rotated_name = f"{log_name}.{timestamp}.log"
    rotated_path = ROTATED_DIR / rotated_name

    print(f"[LogRotator] 日志文件 {size_mb:.1f}MB 超过阈值 {max_size_mb}MB，开始轮转...")

    try:
        # 1. 将当前日志内容复制到归档文件
        shutil.copy2(log_path, rotated_path)
        print(f"[LogRotator] ✅ 已归档到: {rotated_path}")

        # 2. 清空当前日志文件
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"# Log rotated at {timestamp}, archive: {rotated_name}\n")
        print(f"[LogRotator] ✅ 已清空当前日志")

        # 3. 通知 nginx 重新打开日志文件
        if _signal_nginx_reopen():
            print(f"[LogRotator] ✅ nginx 已重新打开日志文件")
        else:
            print(f"[LogRotator] ⚠ nginx reopen 失败，可能需要手动重启 nginx 容器")

    except Exception as e:
        print(f"[LogRotator] ❌ 轮转失败: {e}")
        return None

    # 4. 清理旧归档，保留最近 keep 个
    _cleanup_old_rotations(log_key, keep)

    return rotated_path


def _cleanup_old_rotations(log_key: str, keep: int):
    """清理旧的轮转文件，只保留最近 keep 个"""
    log_path = LOG_PATHS.get(log_key)
    if not log_path:
        return

    log_stem = log_path.stem
    pattern = re.compile(rf"{re.escape(log_stem)}\.\d{{8}}_\d{{6}}\.log$")

    rotated_files = []
    for f in ROTATED_DIR.iterdir():
        if f.is_file() and pattern.match(f.name):
            rotated_files.append(f)

    # 按修改时间排序，旧的在前
    rotated_files.sort(key=lambda f: f.stat().st_mtime)

    # 删除超出保留数量的旧文件
    to_delete = rotated_files[:-keep] if len(rotated_files) > keep else []
    for f in to_delete:
        try:
            f.unlink()
            print(f"[LogRotator] 🗑 已删除旧归档: {f.name}")
        except Exception as e:
            print(f"[LogRotator] ⚠ 删除 {f.name} 失败: {e}")


def get_rotation_info(log_key: str = "nginx_access") -> dict:
    """获取日志轮转状态信息"""
    log_path = LOG_PATHS.get(log_key)
    info = {
        "current_size_mb": get_log_size_mb(log_key),
        "max_size_mb": LOG_MAX_SIZE_MB,
        "keep_count": LOG_ROTATE_KEEP,
        "rotated_count": 0,
        "rotated_files": [],
        "total_archived_mb": 0.0,
    }

    if log_path and ROTATED_DIR.exists():
        log_stem = log_path.stem
        pattern = re.compile(rf"{re.escape(log_stem)}\.\d{{8}}_\d{{6}}\.log$")
        for f in sorted(ROTATED_DIR.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.is_file() and pattern.match(f.name):
                info["rotated_files"].append({
                    "name": f.name,
                    "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                    "time": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
                info["total_archived_mb"] += f.stat().st_size / (1024 * 1024)

        info["rotated_count"] = len(info["rotated_files"])
        info["total_archived_mb"] = round(info["total_archived_mb"], 2)

    return info


def manual_clear_log(log_key: str = "nginx_access") -> bool:
    """手动清空日志（不归档），用于开发调试"""
    log_path = LOG_PATHS.get(log_key)
    if not log_path:
        return False
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(f"# Log cleared at {datetime.now().isoformat()}\n")
        _signal_nginx_reopen()
        print(f"[LogRotator] ✅ 已手动清空 {log_key} 日志")
        return True
    except Exception as e:
        print(f"[LogRotator] ❌ 清空失败: {e}")
        return False
