"""
Pydantic 数据模型定义
统一模块间数据交换格式
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackType(str, Enum):
    SQL_INJECTION = "SQL注入扫描"
    XSS = "XSS攻击"
    CC_FLOOD = "CC并发洪水"
    BRUTE_FORCE = "暴力破解"
    PATH_TRAVERSAL = "路径遍历"
    NORMAL = "正常"


# ============================================
# 日志事件
# ============================================
class ParsedLogLine(BaseModel):
    """LangChain 解析链输出的结构化日志行（单行 nginx access log）"""
    ip: str = ""
    timestamp_raw: str = ""        # 原始时间戳字符串 "22/Jun/2026:15:30:45 +0800"
    method: str = ""
    url: str = ""
    status_code: int = 0
    response_size: int = 0
    user_agent: str = ""


class LogEvent(BaseModel):
    """一条解析后的日志记录"""
    timestamp: datetime
    source: str                    # nginx / mysql / ssh
    log_type: str                  # access / error / slow / auth
    raw_line: str                  # 原始日志行
    ip: Optional[str] = None
    method: Optional[str] = None   # GET / POST / ...
    url: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    error_message: Optional[str] = None
    extra: dict = Field(default_factory=dict)


# ============================================
# 规则匹配结果
# ============================================
class RuleMatch(BaseModel):
    """规则引擎匹配结果"""
    rule_name: str
    rule_type: str                 # frequency / pattern / statistical
    matched_ip: Optional[str] = None
    matched_pattern: Optional[str] = None
    match_count: int = 0
    window_seconds: int = 60
    severity: Severity = Severity.MEDIUM
    description: str = ""


# ============================================
# LLM 分析结果
# ============================================
class LLMAnalysis(BaseModel):
    """LLM 深度分析输出"""
    is_attack: bool
    attack_type: str = "正常"      # SQL注入扫描 / 暴力破解 / CC攻击 / XSS攻击 / 正常
    severity: str = "LOW"           # CRITICAL / HIGH / MEDIUM / LOW
    confidence: float = 0.0         # 置信度 0-1
    attacker_ip: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    affected_endpoints: list[str] = Field(default_factory=list)


# ============================================
# 告警
# ============================================
class Alert(BaseModel):
    """统一告警对象"""
    alert_id: str
    timestamp: datetime
    severity: Severity
    attack_type: str
    source_ip: Optional[str] = None
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    llm_analysis: Optional[LLMAnalysis] = None
    log_samples: list[str] = Field(default_factory=list)  # 相关日志片段
    status: str = "OPEN"           # OPEN / ACKNOWLEDGED / RESOLVED
    auto_rescue_triggered: bool = False


# ============================================
# 救援任务
# ============================================
class RescueAction(BaseModel):
    """救援剧本中的单个操作"""
    name: str
    command: str
    description: str
    rollback_command: Optional[str] = None


class RescueTask(BaseModel):
    """救援执行任务"""
    task_id: str
    alert_id: str
    attack_type: str
    attacker_ip: str
    actions: list[RescueAction] = Field(default_factory=list)
    status: str = "PENDING"        # PENDING / RUNNING / SUCCESS / FAILED / ROLLED_BACK
    results: list[dict] = Field(default_factory=list)


# ============================================
# 事件总线消息
# ============================================
class EventBusMessage(BaseModel):
    """模块间事件消息"""
    event_type: str                # LOG_DETECTED / RULE_MATCHED / LLM_ANALYZED / ALERT_CREATED / RESCUE_TRIGGERED
    payload: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    source_module: str = ""
