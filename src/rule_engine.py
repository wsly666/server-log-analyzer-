"""
规则引擎 (Member C)
第一层检测：阈值判断 + 正则特征匹配
毫秒级响应，过滤掉 99% 的正常日志
"""

import re
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import unquote

from src.models import LogEvent, RuleMatch, Severity
from src.config import (
    FREQ_THRESHOLD, WINDOW_SECONDS,
    SQL_INJECTION_PATTERNS, XSS_PATTERNS, PATH_TRAVERSAL_PATTERNS,
)
from src.event_bus import event_bus, EventBusMessage


class SlidingWindow:
    """滑动窗口计数器 —— O(1) 复杂度

    使用事件时间戳作为基准（而非 datetime.now()），
    避免 nginx 容器 UTC 时间与宿主机本地时间不一致导致窗口失效。
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._events: deque = deque()

    def add(self, timestamp: datetime):
        """添加一个事件"""
        self._events.append(timestamp)

    def count(self) -> int:
        """清理过期事件并返回窗口内事件数"""
        if not self._events:
            return 0
        # 以最新事件时间为基准，避免 datetime.now() 与日志时区不一致
        newest = self._events[-1]
        cutoff = newest - timedelta(seconds=self.window)
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)

    def clear(self):
        self._events.clear()


class RuleEngine:
    """规则引擎"""

    def __init__(self):
        # IP -> 滑动窗口
        self._ip_windows: dict[str, SlidingWindow] = {}
        # URL -> 滑动窗口 (用于检测CC)
        self._url_windows: dict[str, SlidingWindow] = {}
        # 暴力破解: IP -> (login失败次数, 滑动窗口)
        self._brute_force_windows: dict[str, SlidingWindow] = {}
        # 错误计数
        self._error_count = 0
        self._total_count = 0
        self._error_window = deque()

        # 编译正则
        self.sql_patterns = [re.compile(p) for p in SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(p) for p in XSS_PATTERNS]
        self.path_patterns = [re.compile(p) for p in PATH_TRAVERSAL_PATTERNS]

    def analyze(self, event: LogEvent) -> list[RuleMatch]:
        """分析一个日志事件，返回所有匹配的规则"""
        matches = []

        # 规则1：频率检测（同一IP高频请求）
        if event.ip:
            match = self._check_frequency(event)
            if match:
                matches.append(match)

        # 规则2：特征检测（SQL注入/XSS/路径遍历）
        if event.url:
            matches.extend(self._check_patterns(event))

        # 规则3：错误率检测 (5xx)
        if event.status_code and event.status_code >= 500:
            match = self._check_error_rate(event)
            if match:
                matches.append(match)

        # 规则4：暴力破解检测 (大量 POST /login + 401)
        if event.method and event.url and event.status_code:
            match = self._check_brute_force(event)
            if match:
                matches.append(match)

        return matches

    def _check_frequency(self, event: LogEvent) -> Optional[RuleMatch]:
        """检测同一IP的请求频率"""
        if event.ip not in self._ip_windows:
            self._ip_windows[event.ip] = SlidingWindow(WINDOW_SECONDS)
        self._ip_windows[event.ip].add(event.timestamp)
        count = self._ip_windows[event.ip].count()

        if count > FREQ_THRESHOLD:
            return RuleMatch(
                rule_name="高频访问检测",
                rule_type="frequency",
                matched_ip=event.ip,
                match_count=count,
                window_seconds=WINDOW_SECONDS,
                severity=Severity.MEDIUM,
                description=f"IP {event.ip} 在 {WINDOW_SECONDS}秒 内发起了 {count} 次请求 (阈值: {FREQ_THRESHOLD})",
            )
        return None

    def _check_patterns(self, event: LogEvent) -> list[RuleMatch]:
        """检测URL中的攻击特征"""
        matches = []
        url = event.url or ""
        decoded_url = unquote(url)  # URL decode: %20→空格, %27→' 等

        # SQL注入特征
        for i, pattern in enumerate(self.sql_patterns):
            if pattern.search(decoded_url):
                matches.append(RuleMatch(
                    rule_name=f"SQL注入特征-{i+1}",
                    rule_type="pattern",
                    matched_ip=event.ip,
                    matched_pattern=pattern.pattern,
                    severity=Severity.HIGH,
                    description=f"URL中包含SQL注入特征: {url[:100]}",
                ))
                break  # 同一类不重复报

        # XSS特征
        for i, pattern in enumerate(self.xss_patterns):
            if pattern.search(decoded_url):
                matches.append(RuleMatch(
                    rule_name=f"XSS特征-{i+1}",
                    rule_type="pattern",
                    matched_ip=event.ip,
                    matched_pattern=pattern.pattern,
                    severity=Severity.HIGH,
                    description=f"URL中包含XSS攻击特征: {url[:100]}",
                ))
                break

        # 路径遍历特征
        for i, pattern in enumerate(self.path_patterns):
            if pattern.search(decoded_url):
                matches.append(RuleMatch(
                    rule_name=f"路径遍历-{i+1}",
                    rule_type="pattern",
                    matched_ip=event.ip,
                    matched_pattern=pattern.pattern,
                    severity=Severity.HIGH,
                    description=f"URL中包含路径遍历特征: {url[:100]}",
                ))
                break

        return matches

    def _check_error_rate(self, event: LogEvent) -> Optional[RuleMatch]:
        """检测错误率"""
        self._total_count += 1
        if event.status_code and event.status_code >= 500:
            self._error_count += 1
            self._error_window.append(event.timestamp)

        # 清理过期 — 使用事件时间戳，避免时区问题
        cutoff = event.timestamp - timedelta(seconds=WINDOW_SECONDS)
        while self._error_window and self._error_window[0] < cutoff:
            self._error_window.popleft()

        recent_errors = len(self._error_window)
        if self._total_count > 10 and recent_errors / max(self._total_count, 1) > 0.3:
            return RuleMatch(
                rule_name="5xx错误率异常",
                rule_type="statistical",
                severity=Severity.HIGH,
                match_count=recent_errors,
                window_seconds=WINDOW_SECONDS,
                description=f"5xx错误率 {recent_errors/max(self._total_count,1)*100:.1f}% 超过阈值",
            )
        return None

    def _check_brute_force(self, event: LogEvent) -> Optional[RuleMatch]:
        """检测暴力破解：同一IP大量 POST /login 返回 401"""
        if not (event.ip and event.method and event.url and event.status_code):
            return None

        # 仅检测 /login 端点的 POST 请求返回 401
        if not (event.method.upper() == "POST" and "/login" in event.url and event.status_code == 401):
            return None

        if event.ip not in self._brute_force_windows:
            self._brute_force_windows[event.ip] = SlidingWindow(WINDOW_SECONDS)
        self._brute_force_windows[event.ip].add(event.timestamp)
        count = self._brute_force_windows[event.ip].count()

        # 同一IP 60秒内 POST /login 401 超过 20 次 → 暴力破解
        if count > 20:
            return RuleMatch(
                rule_name="暴力破解检测",
                rule_type="frequency",
                matched_ip=event.ip,
                match_count=count,
                window_seconds=WINDOW_SECONDS,
                severity=Severity.HIGH,
                description=f"IP {event.ip} 在 {WINDOW_SECONDS}秒 内对 /login 发起 {count} 次失败登录 (401)",
            )
        return None

    def get_suspicious_logs(self, events: list[LogEvent]) -> list[LogEvent]:
        """批量筛选可疑日志"""
        suspicious = []
        for event in events:
            matches = self.analyze(event)
            if matches:
                suspicious.append(event)
        return suspicious

    def reset(self):
        """重置所有计数器"""
        self._ip_windows.clear()
        self._url_windows.clear()
        self._brute_force_windows.clear()
        self._error_count = 0
        self._total_count = 0
        self._error_window.clear()


# 全局单例
rule_engine = RuleEngine()
