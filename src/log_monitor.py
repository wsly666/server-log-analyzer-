"""
日志监控器 (Member C)
使用 watchdog 实时监听日志文件变化，双重解析模式提取字段：
  - 默认：正则表达式解析（毫秒级、免费）
  - 可选：LangChain LLM 解析链（满足技术栈要求）
"""

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.models import LogEvent, ParsedLogLine
from src.config import LOG_PATHS, LOG_PARSER_USE_LLM
from src.event_bus import event_bus, EventBusMessage


# ============================================
# Nginx 日志解析器
# ============================================
NGINX_ACCESS_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'          # IP
    r'-\s+'                                      # remote_user (占位)
    r'-\s+'                                      # auth_user (占位)
    r'\[(?P<timestamp>[^\]]+)\]\s+'             # 时间戳
    r'"(?P<request>[^"]+)"\s+'                   # 完整请求行 (含可能含空格的URL)
    r'(?P<status>\d{3})\s+'                      # 状态码
    r'(?P<size>\d+)\s+'                          # 响应大小
    r'"(?P<referer>[^"]*)"\s+'                   # Referer
    r'"(?P<user_agent>[^"]*)"'                   # User-Agent
)

NGINX_ERROR_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<message>.*)'
)


# ============================================
# LangChain LLM 日志解析链（可选模式）
# ============================================
NGINX_LOG_PARSER_SYSTEM_PROMPT = """你是一个专业的 Nginx 日志解析器。从原始访问日志行中提取结构化字段。

Nginx combined 日志格式：
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

示例输入：
  192.168.1.100 - - [22/Jun/2026:15:30:45 +0800] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0 ..."

示例输出：
  ip: 192.168.1.100
  timestamp_raw: 22/Jun/2026:15:30:45 +0800
  method: POST
  url: /login
  status_code: 401
  response_size: 128
  user_agent: Mozilla/5.0 ...

要求：只输出 JSON，不要任何解释文字。"""

_llm_log_parser = None  # 懒加载单例


def _get_llm_log_parser():
    """懒加载 LangChain 解析链（避免启动时导入耗时）"""
    global _llm_log_parser
    if _llm_log_parser is not None:
        return _llm_log_parser

    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import PydanticOutputParser
    from src.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

    parser = PydanticOutputParser(pydantic_object=ParsedLogLine)
    prompt = ChatPromptTemplate.from_messages([
        ("system", NGINX_LOG_PARSER_SYSTEM_PROMPT),
        ("human", "请解析这条 Nginx 日志: {log_line}\n\n{format_instructions}"),
    ]).partial(format_instructions=parser.get_format_instructions())

    llm = ChatOpenAI(
        api_key=LLM_API_KEY,
        base_url=LLM_BASE_URL,
        model=LLM_MODEL,
        temperature=0,
        max_tokens=512,
    )

    _llm_log_parser = prompt | llm | parser
    return _llm_log_parser


def parse_nginx_access_line_llm(line: str) -> Optional[LogEvent]:
    """使用 LangChain LLM 解析链解析 nginx access.log 的一行"""
    try:
        chain = _get_llm_log_parser()
        parsed: ParsedLogLine = chain.invoke({"log_line": line})

        # 转换时间戳
        ts = None
        ts_formats = [
            "%d/%b/%Y:%H:%M:%S %z",     # 22/Jun/2026:15:30:45 +0800
            "%Y-%m-%dT%H:%M:%S%z",       # ISO
            "%Y-%m-%d %H:%M:%S",         # fallback
        ]
        for fmt in ts_formats:
            try:
                ts = datetime.strptime(parsed.timestamp_raw, fmt).replace(tzinfo=None)
                break
            except ValueError:
                continue
        if ts is None:
            ts = datetime.now()

        return LogEvent(
            timestamp=ts,
            source="nginx",
            log_type="access",
            raw_line=line.strip(),
            ip=parsed.ip or None,
            method=parsed.method or "GET",
            url=parsed.url or "/",
            status_code=parsed.status_code or 0,
            response_size=parsed.response_size or 0,
            user_agent=parsed.user_agent or None,
        )
    except Exception as e:
        print(f"[LLMParser] 解析失败，回退到正则: {e}")
        return None


def parse_nginx_access_line(line: str) -> Optional[LogEvent]:
    """解析 nginx access.log 的一行（默认正则，可选 LangChain LLM）"""
    if LOG_PARSER_USE_LLM:
        # 优先尝试 LLM，失败回退正则
        result = parse_nginx_access_line_llm(line)
        if result is not None:
            return result
        # LLM 失败，继续走正则

    match = NGINX_ACCESS_PATTERN.search(line)
    if not match:
        return None

    try:
        ts = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        ts = datetime.now()

    # 从完整请求行中提取 method 和 url (url可能含空格)
    request = match.group("request")
    # 格式: "METHOD URL HTTP/x.x" — 从末尾找 " HTTP/" 分割
    parts = request.rsplit(" HTTP/", 1)
    if len(parts) == 2:
        method_and_url = parts[0]
        method_url_parts = method_and_url.split(" ", 1)
        method = method_url_parts[0] if method_url_parts else "GET"
        url = method_url_parts[1] if len(method_url_parts) > 1 else "/"
    else:
        # fallback
        segs = request.split()
        method = segs[0] if segs else "GET"
        url = segs[1] if len(segs) > 1 else "/"

    return LogEvent(
        timestamp=ts,
        source="nginx",
        log_type="access",
        raw_line=line.strip(),
        ip=match.group("ip"),
        method=method,
        url=url,
        status_code=int(match.group("status")),
        response_size=int(match.group("size")),
        user_agent=match.group("user_agent"),
    )


def parse_nginx_error_line(line: str) -> Optional[LogEvent]:
    """解析 nginx error.log 的一行"""
    match = NGINX_ERROR_PATTERN.search(line)
    if not match:
        return None

    try:
        ts = datetime.strptime(match.group("timestamp"), "%Y/%m/%d %H:%M:%S")
    except ValueError:
        ts = datetime.now()

    return LogEvent(
        timestamp=ts,
        source="nginx",
        log_type="error",
        raw_line=line.strip(),
        error_message=match.group("message"),
    )


# ============================================
# 日志文件监控器
# ============================================
class LogFileHandler(FileSystemEventHandler):
    """watchdog 文件事件处理器"""

    def __init__(self, source: str, parser_func):
        self.source = source
        self.parser = parser_func
        self._last_position = 0

    def on_modified(self, event):
        if event.is_directory:
            return
        self._read_new_lines(event.src_path)

    def _read_new_lines(self, filepath: str):
        """读取文件新增的行"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, 2)  # 跳到文件末尾
                file_size = f.tell()

                if file_size < self._last_position:
                    # 文件被轮转，从头读
                    self._last_position = 0

                f.seek(self._last_position)
                new_content = f.read()
                self._last_position = file_size

                for line in new_content.strip().split("\n"):
                    if line.strip():
                        event = self.parser(line)
                        if event:
                            self._publish_event(event)
        except Exception as e:
            print(f"[LogFileHandler] Error reading {filepath}: {e}")

    def _publish_event(self, event: LogEvent):
        """发布日志事件到事件总线"""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(
                    event_bus.publish(EventBusMessage(
                        event_type="LOG_DETECTED",
                        payload=event.model_dump(mode="json"),
                        source_module="log_monitor",
                    ))
                )
        except RuntimeError:
            pass


class LogMonitor:
    """日志监控器 —— 协调 watchdog 监听多个日志文件"""

    def __init__(self):
        self.observer = Observer()
        self._handlers = []

    def start(self):
        """启动所有日志文件的监控"""
        # 监控 nginx access.log
        nginx_access_path = str(LOG_PATHS["nginx_access"].parent)
        handler = LogFileHandler("nginx_access", parse_nginx_access_line)
        self.observer.schedule(handler, nginx_access_path, recursive=False)
        self._handlers.append(handler)

        # 监控 nginx error.log
        nginx_error_path = str(LOG_PATHS["nginx_error"].parent)
        handler2 = LogFileHandler("nginx_error", parse_nginx_error_line)
        self.observer.schedule(handler2, nginx_error_path, recursive=False)
        self._handlers.append(handler2)

        self.observer.start()
        print("[LogMonitor] ✅ 日志监控已启动")

    def stop(self):
        """停止监控"""
        self.observer.stop()
        self.observer.join(timeout=5)
        print("[LogMonitor] ⏹ 日志监控已停止")

    def tail_log(self, log_key: str, lines: int = 20) -> list[str]:
        """读取最近的日志行（用于界面展示）"""
        log_path = LOG_PATHS.get(log_key)
        if not log_path or not log_path.exists():
            return []
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
                return [l.strip() for l in all_lines[-lines:]]
        except Exception:
            return []


# 全局单例
log_monitor = LogMonitor()
