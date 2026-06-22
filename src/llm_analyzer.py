"""
LLM 深度分析模块 (Member C)
第二层检测：将规则引擎筛选出的可疑日志发送给 LLM 进行语义级分析
使用 LangChain StructuredOutput 确保输出格式
"""

import json
import asyncio
from datetime import datetime
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate

from src.models import LogEvent, LLMAnalysis, RuleMatch
from src.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_TEMPERATURE, LLM_MAX_TOKENS,
)


# ============================================
# LLM Prompt 模板
# ============================================
ANALYSIS_SYSTEM_PROMPT = """你是一个资深安全运维专家，拥有10年安全运营经验。
你的任务是分析服务器访问日志，判断是否存在安全攻击行为。

分析规则：
1. SQL注入扫描：URL中包含 SQL 关键字（UNION SELECT、DROP TABLE、' OR '1'='1、--注释符等），且短时间内大量同类请求
2. XSS攻击：URL中包含 <script>、onerror=、javascript: 等脚本注入特征
3. CC洪水：同一IP在短时间内（30秒）对同一URL发起>50次请求
4. 暴力破解：同一IP对 /login 接口短时间内发起>20次POST请求，且全部返回401
5. 路径遍历：URL中包含 ../../、/etc/passwd 等文件路径特征

输出要求：
- is_attack: 是否确认为攻击（true/false）
- attack_type: 攻击类型（"SQL注入扫描" / "XSS攻击" / "CC并发洪水" / "暴力破解" / "路径遍历" / "正常"）
- severity: 严重等级（"CRITICAL" / "HIGH" / "MEDIUM" / "LOW"）
- confidence: 置信度（0.0-1.0）
- attacker_ip: 攻击者IP
- description: 攻击行为详细描述
- recommendation: 具体处置建议（多步骤用分号分隔）
- affected_endpoints: 受影响接口列表

注意：
- 结合请求频率、时间密度、payload多样性综合判断
- 暴力破解与正常用户输错密码的区别：暴力破解用户名多样性高、频率高、时间间隔均匀
- 如果日志量较少不足以判断，confidence 设为 0.5 以下
- 只输出JSON，不要输出其他内容"""


class LLMAnalyzer:
    """LLM 深度分析器"""

    def __init__(self):
        self.llm = ChatOpenAI(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            max_tokens=LLM_MAX_TOKENS,
        )
        self.parser = PydanticOutputParser(pydantic_object=LLMAnalysis)

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", ANALYSIS_SYSTEM_PROMPT),
            ("human", "{log_data}"),
        ])

        self.chain = self.prompt | self.llm | self.parser

    def _format_logs_for_llm(self, events: list[LogEvent],
                              rule_matches: list[RuleMatch]) -> str:
        """格式化日志数据供 LLM 分析"""
        # 先做聚合摘要
        ip_counts: dict[str, int] = {}
        url_counts: dict[str, int] = {}
        status_counts: dict[int, int] = {}
        sample_lines: list[str] = []

        for event in events:
            if event.ip:
                ip_counts[event.ip] = ip_counts.get(event.ip, 0) + 1
            if event.url:
                url_counts[event.url] = url_counts.get(event.url, 0) + 1
            if event.status_code:
                status_counts[event.status_code] = status_counts.get(event.status_code, 0) + 1
            sample_lines.append(event.raw_line)

        # 规则匹配摘要
        rules_summary = []
        for m in rule_matches:
            rules_summary.append(f"  - {m.rule_name}: {m.description} (严重度: {m.severity.value})")

        # 构建分析文本
        text = f"""请分析以下服务器日志：

【基本信息】
- 分析时间：{datetime.now().isoformat()}
- 可疑日志总数：{len(events)} 条
- 涉及IP数：{len(ip_counts)} 个

【IP请求量分布】
"""
        for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1]):
            text += f"  {ip}: {count} 次请求\n"

        text += "\n【规则引擎预判】\n"
        text += "\n".join(rules_summary) if rules_summary else "  无规则命中\n"

        text += f"\n【日志样本】（共{len(sample_lines)}条，展示最近50条）\n"
        for line in sample_lines[-50:]:
            text += f"  {line}\n"

        text += "\n请输出 JSON 格式的分析结果。"
        return text

    def analyze(self, events: list[LogEvent],
                rule_matches: list[RuleMatch]) -> LLMAnalysis:
        """分析日志事件，返回 LLM 分析结果"""
        if not events:
            return LLMAnalysis(
                is_attack=False,
                attack_type="正常",
                severity="LOW",
                confidence=0.0,
                description="无日志事件需要分析",
            )

        try:
            log_text = self._format_logs_for_llm(events, rule_matches)
            result = self.chain.invoke({"log_data": log_text})
            return result
        except Exception as e:
            print(f"[LLMAnalyzer] 分析失败: {e}")
            # 降级：如果LLM失败，根据规则引擎结果生成基本分析
            return self._fallback_analysis(events, rule_matches)

    def _fallback_analysis(self, events: list[LogEvent],
                            rule_matches: list[RuleMatch]) -> LLMAnalysis:
        """LLM 失败时的降级分析"""
        if not rule_matches:
            return LLMAnalysis(
                is_attack=False,
                attack_type="正常",
                severity="LOW",
                confidence=0.0,
                description="降级模式：无规则命中",
            )

        severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for m in rule_matches:
            severities[m.severity.value] = severities.get(m.severity.value, 0) + 1

        if severities["HIGH"] >= 2 or severities["CRITICAL"] > 0:
            severity = "HIGH"
        elif severities["HIGH"] >= 1 or severities["MEDIUM"] >= 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # 从规则匹配推断攻击类型
        attack_type = "正常"
        for m in rule_matches:
            if "SQL" in m.rule_name:
                attack_type = "SQL注入扫描"
                break
            elif "XSS" in m.rule_name:
                attack_type = "XSS攻击"
                break
            elif "路径" in m.rule_name:
                attack_type = "路径遍历"
                break
            elif "暴力破解" in m.rule_name:
                attack_type = "暴力破解"
                break
            elif "高频" in m.rule_name:
                attack_type = "CC并发洪水"
                break

        return LLMAnalysis(
            is_attack=attack_type != "正常",
            attack_type=attack_type,
            severity=severity,
            confidence=0.6,
            attacker_ip=events[0].ip if events else None,
            description=f"降级模式分析：基于 {len(rule_matches)} 条规则命中推断",
            recommendation="建议人工确认",
        )


# 全局单例
llm_analyzer = LLMAnalyzer()
