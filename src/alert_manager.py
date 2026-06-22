"""
告警管理器 (Member C)
纯工厂模式：创建、确认、解决告警。不持有任何可变状态。
去重缓存由调用方 (Streamlit session_state) 管理。
"""

import hashlib
from datetime import datetime
from typing import Optional

from src.models import Alert, LogEvent, RuleMatch, LLMAnalysis, Severity
from src.config import SEVERITY_LEVELS


class AlertManager:
    """告警管理器 —— 无状态工厂"""

    def __init__(self):
        self._handlers: list = []  # 告警处理回调

    def create_alert(self, events: list[LogEvent],
                     rule_matches: list[RuleMatch],
                     llm_analysis: Optional[LLMAnalysis],
                     dedup_cache: dict,
                     dedup_window: int = 300) -> Optional[Alert]:
        """
        创建告警（带去重）。

        Args:
            events: 可疑日志事件列表
            rule_matches: 规则引擎命中列表
            llm_analysis: LLM 分析结果
            dedup_cache: 外部管理的去重缓存 dict, key=dedup_hash, value=datetime
            dedup_window: 去重窗口 (秒)

        Returns:
            新创建的 Alert 对象，如果被去重则返回 None
        """
        source_ip = events[0].ip if events else "unknown"
        attack_type = llm_analysis.attack_type if llm_analysis else "未知"

        dedup_key = hashlib.md5(
            f"{source_ip}:{attack_type}".encode()
        ).hexdigest()

        now = datetime.now()
        if dedup_key in dedup_cache:
            last_time = dedup_cache[dedup_key]
            if (now - last_time).total_seconds() < dedup_window:
                print(f"[AlertManager] ⚠ 去重命中: {source_ip}:{attack_type} "
                      f"(上次告警: {last_time.strftime('%H:%M:%S')}, "
                      f"距今 {(now - last_time).total_seconds():.0f}s)")
                return None

        dedup_cache[dedup_key] = now

        # 确定严重等级
        severity = self._determine_severity(rule_matches, llm_analysis)

        # 创建告警
        alert_id = f"ALT-{now.strftime('%Y%m%d%H%M%S')}-{hashlib.md5(dedup_key.encode()).hexdigest()[:6]}"
        alert = Alert(
            alert_id=alert_id,
            timestamp=now,
            severity=severity,
            attack_type=attack_type,
            source_ip=source_ip,
            rule_matches=rule_matches,
            llm_analysis=llm_analysis,
            log_samples=[e.raw_line for e in events[-10:]],
            status="OPEN",
            auto_rescue_triggered=(severity == Severity.CRITICAL),
        )

        # 触发回调
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"[AlertManager] Handler error: {e}")

        print(f"[AlertManager] ✅ 告警已创建: {alert_id} | {attack_type} | {severity.value} | IP: {source_ip}")
        return alert

    def _determine_severity(self, rule_matches: list[RuleMatch],
                            llm_analysis: Optional[LLMAnalysis]) -> Severity:
        """综合规则匹配和LLM分析确定严重等级"""
        if llm_analysis and llm_analysis.severity:
            llm_sev = llm_analysis.severity.upper()
            if llm_sev in SEVERITY_LEVELS:
                return Severity(llm_sev)

        max_sev = Severity.INFO
        for m in rule_matches:
            if SEVERITY_LEVELS.get(m.severity.value, -1) > SEVERITY_LEVELS.get(max_sev.value, -1):
                max_sev = m.severity
        return max_sev

    def acknowledge_alert(self, alert: Alert):
        """确认告警"""
        alert.status = "ACKNOWLEDGED"

    def resolve_alert(self, alert: Alert):
        """解决告警"""
        alert.status = "RESOLVED"

    def register_handler(self, handler):
        """注册告警处理回调函数"""
        self._handlers.append(handler)

    @staticmethod
    def get_stats(alerts: list[Alert]) -> dict:
        """从告警列表计算统计"""
        total = len(alerts)
        critical = sum(1 for a in alerts if a.severity == Severity.CRITICAL)
        high = sum(1 for a in alerts if a.severity == Severity.HIGH)
        resolved = sum(1 for a in alerts if a.status == "RESOLVED")
        return {
            "total_alerts": total,
            "critical": critical,
            "high": high,
            "active": total - resolved,
            "resolved": resolved,
            "auto_rescued": sum(1 for a in alerts if a.auto_rescue_triggered),
        }


# 全局单例 (无状态，安全共享)
alert_manager = AlertManager()
