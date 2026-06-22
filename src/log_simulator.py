"""
正常日志生成器 (Member B)
模拟真实用户浏览行为，生成 nginx 格式的正常访问日志
"""

import time
import random
import threading
import sys
from datetime import datetime
from pathlib import Path

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import NORMAL_TRAFFIC_CONFIG, LOG_PATHS, NGINX_PORT


class LogSimulator:
    """正常用户流量日志生成器"""

    def __init__(self):
        self.config = NORMAL_TRAFFIC_CONFIG
        self.running = False
        self.thread: threading.Thread | None = None
        self.log_path = LOG_PATHS["nginx_access"]

    def _generate_nginx_log_line(self, ip: str, page: str, status: int,
                                  size: int, ua: str) -> str:
        """生成一条 nginx combined 格式日志"""
        now = datetime.now()
        timestamp = now.strftime("%d/%b/%Y:%H:%M:%S +0800")

        methods = ["GET", "GET", "GET", "GET", "POST"]  # 80% GET, 20% POST
        method = random.choice(methods)

        return (
            f'{ip} - - [{timestamp}] "{method} {page} HTTP/1.1" '
            f'{status} {size} "-" "{ua}"\n'
        )

    def _generate_batch(self):
        """生成一批日志（模拟一秒内的请求）"""
        lines = []
        batch_size = random.randint(
            max(1, self.config["rate_per_second"] - 1),
            self.config["rate_per_second"] + 2
        )

        for _ in range(batch_size):
            # 随机生成正常用户
            ip = f"192.168.1.{random.randint(2, 50)}"
            page = random.choice(self.config["pages"])
            ua = random.choice(self.config["user_agents"])

            # 正常请求：大部分返回 200，偶尔 304/404
            status = random.choices(
                [200, 304, 404],
                weights=[7, 1, 1]
            )[0]
            size = random.randint(200, 50000)

            lines.append(self._generate_nginx_log_line(ip, page, status, size, ua))

        return lines

    def _run_loop(self):
        """主循环：持续生成日志"""
        # 确保日志目录存在
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.log_path, "a", encoding="utf-8") as f:
            while self.running:
                try:
                    batch = self._generate_batch()
                    for line in batch:
                        f.write(line)
                    f.flush()
                    time.sleep(1.0)
                except Exception as e:
                    print(f"[LogSimulator] Error: {e}")
                    time.sleep(1)

    def start(self):
        """启动日志生成"""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        print(f"[LogSimulator] ✅ 正常日志流已启动 ({self.config['rate_per_second']} req/s)")

    def stop(self):
        """停止日志生成"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        print("[LogSimulator] ⏹ 正常日志流已停止")


if __name__ == "__main__":
    sim = LogSimulator()
    try:
        sim.start()
        print("正常日志生成中... Ctrl+C 停止")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sim.stop()
