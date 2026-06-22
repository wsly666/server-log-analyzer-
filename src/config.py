"""
全局配置模块
统一管理所有路径、API Key、阈值参数
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ============================================
# 项目路径
# ============================================
PROJECT_ROOT = Path(__file__).parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"
REPORTS_DIR = PROJECT_ROOT / "reports"
CHARTS_DIR = PROJECT_ROOT / "charts"
DOCKER_DIR = PROJECT_ROOT / "docker"
ROTATED_DIR = LOGS_DIR / "rotated"     # 轮转日志存档目录

# 日志轮转配置
LOG_MAX_SIZE_MB = 50        # 日志文件超过此大小自动轮转 (MB)
LOG_ROTATE_KEEP = 5         # 保留最近 N 个轮转文件

# 日志文件路径
LOG_PATHS = {
    "nginx_access": LOGS_DIR / "nginx" / "access.log",
    "nginx_error": LOGS_DIR / "nginx" / "error.log",
    "mysql_error": LOGS_DIR / "mysql" / "error.log",
    "mysql_slow": LOGS_DIR / "mysql" / "slow.log",
    "ssh_auth": LOGS_DIR / "ssh" / "auth.log",
}

# ============================================
# LLM 配置
# ============================================
LLM_API_KEY = os.getenv("LLM_API_KEY", "your-api-key-here")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_TEMPERATURE = 0.1
LLM_MAX_TOKENS = 4096

# ============================================
# Docker 容器配置
# ============================================
NGINX_PORT = 8080
MYSQL_PORT = 3306
SSH_TARGET_PORT = 2222
SSH_USERNAME = "root"  # 需要 root 执行 iptables 等救援命令
SSH_PASSWORD = "rescue123"

# ============================================
# 邮件配置
# ============================================
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "your-email@qq.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-auth-code")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "admin@company.com")

# ============================================
# 日志解析器配置
# ============================================
LOG_PARSER_USE_LLM = False       # True=使用 LangChain LLM 解析链, False=使用正则（默认）

# ============================================
# 检测引擎配置
# ============================================
# 规则引擎阈值
FREQ_THRESHOLD = 30          # 同一IP 60秒内请求数阈值
BRUTE_FORCE_THRESHOLD = 20   # 同一IP 60秒内 POST /login 401 阈值
ERROR_RATE_THRESHOLD = 0.3   # 5xx错误率阈值 (30%)
WINDOW_SECONDS = 60          # 滑动窗口大小
ALERT_DEDUP_WINDOW = 120     # 告警去重窗口 (2分钟，适合演示)

# SQL注入特征正则
SQL_INJECTION_PATTERNS = [
    r"(?i)(union.*select|select.*from|insert.*into|drop\s+table|alter\s+table)",
    r"(?i)('|\")\s*OR\s+('?\d+'?|[^=]+)=\s*('?\d+'?|[^=]+)",
    r"(?i)--[\s]*$|#[\s]*$|/\*.*\*/",
    r"(?i)(information_schema|benchmark\s*\(|sleep\s*\()",
]

# XSS攻击特征正则
XSS_PATTERNS = [
    r"(?i)(<script[^>]*>|</script>)",
    r"(?i)(javascript\s*:|onerror\s*=|onload\s*=)",
    r"(?i)(<img[^>]+onerror|alert\s*\(|prompt\s*\()",
    r"(?i)(document\.cookie|window\.location)",
]

# 路径遍历特征
PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\./|\.\.\%2f|\.\.\%5c)",
    r"(?i)(/etc/passwd|/etc/shadow|boot\.ini)",
    r"(?i)(\.\.\\\.\./)",
]

# CC攻击特征
CC_PATTERNS = [
    # 同一URL短时间内大量请求
]

# ============================================
# 告警严重等级
# ============================================
SEVERITY_LEVELS = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
    "INFO": -1,
}

# ============================================
# 攻击模拟器配置
# ============================================
ATTACK_CONFIG = {
    "sql_injection": {
        "threads": 5,
        "requests_per_thread": 100,
        "delay_between_requests": 0.01,
    },
    "xss": {
        "threads": 3,
        "requests_per_thread": 50,
        "delay_between_requests": 0.02,
    },
    "cc_flood": {
        "threads": 20,
        "requests_per_thread": 200,
        "delay_between_requests": 0.001,
    },
    "brute_force": {
        "threads": 10,
        "attempts_per_thread": 30,
        "delay_between_attempts": 0.05,
    },
}

# 正常流量配置
NORMAL_TRAFFIC_CONFIG = {
    "rate_per_second": 3,      # 每秒请求数
    "pages": ["/", "/about", "/products", "/contact", "/blog", "/api/status", "/docs"],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    ],
}
