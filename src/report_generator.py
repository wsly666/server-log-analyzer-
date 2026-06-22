"""
报告生成器 (Member D)
使用 LLM 根据告警详情自动生成 Markdown 分析报告
"""

from datetime import datetime
from pathlib import Path

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate

from src.models import Alert, LLMAnalysis
from src.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_TEMPERATURE,
    REPORTS_DIR,
)


REPORT_SYSTEM_PROMPT = """你是一个资深安全运维报告撰写专家。请根据提供的告警信息，生成一份专业的安全事件分析报告。

报告要求：
1. 使用中文撰写
2. 包含以下章节：事件概述、异常详情、处置措施、后续建议
3. 使用 Markdown 格式，包含适当的表情符号
4. 技术细节要准确，同时语言要通俗易懂
5. 使用分隔线和标题使结构清晰
6. 不要编造不存在的数据"""


class ReportGenerator:
    """LLM 驱动的安全事件报告生成器"""

    def __init__(self):
        self.llm = ChatOpenAI(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            max_tokens=2048,
        )
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", REPORT_SYSTEM_PROMPT),
            ("human", "{alert_data}"),
        ])
        self.chain = self.prompt | self.llm

    def generate(self, alert: Alert, rescue_task=None) -> str:
        """根据告警生成分析报告"""

        # 构建告警数据摘要
        alert_data = self._format_alert_data(alert, rescue_task)

        try:
            response = self.chain.invoke({"alert_data": alert_data})
            report = response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            print(f"[ReportGenerator] LLM 生成失败: {e}")
            report = self._fallback_report(alert, rescue_task)

        # 保存报告
        report_path = REPORTS_DIR / f"report_{alert.alert_id}.md"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"[ReportGenerator] ✅ 报告已保存: {report_path}")
        return report

    def _format_alert_data(self, alert: Alert, rescue_task=None) -> str:
        """格式化告警数据供 LLM 使用"""
        text = f"""请为以下安全事件生成分析报告：

【基本信息】
- 告警ID：{alert.alert_id}
- 告警时间：{alert.timestamp.isoformat()}
- 严重等级：{alert.severity.value}
- 攻击类型：{alert.attack_type}
- 攻击IP：{alert.source_ip}

【LLM分析结果】
"""
        if alert.llm_analysis:
            a = alert.llm_analysis
            text += f"""
- 确认为攻击: {'是' if a.is_attack else '否'}
- 攻击类型: {a.attack_type}
- 置信度: {a.confidence:.0%}
- 分析描述: {a.description}
- 处置建议: {a.recommendation}
- 受影响接口: {', '.join(a.affected_endpoints) if a.affected_endpoints else '无'}
"""

        text += "\n【规则引擎命中】\n"
        for m in alert.rule_matches:
            text += f"- {m.rule_name}: {m.description}\n"

        if rescue_task:
            text += f"""
【救援执行情况】
- 救援任务ID: {rescue_task.task_id}
- 执行状态: {rescue_task.status}
- 执行步骤:
"""
            for r in rescue_task.results:
                icon = "✅" if r.get("success") else "❌"
                text += f"  {icon} {r.get('action')}: {r.get('command', '')[:80]}\n"

        text += f"""
【相关日志样本】
```
{chr(10).join(alert.log_samples[:20])}
```
"""
        return text

    def _fallback_report(self, alert: Alert, rescue_task=None) -> str:
        """LLM 失败时的降级报告"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"""==========================================
    服务器安全事件分析报告
    生成时间：{now}
==========================================

【事件概述】
检测到来自 IP {alert.source_ip} 的 {alert.attack_type} 攻击。
系统已自动执行应急处置。

【异常详情】
├─ 告警ID：{alert.alert_id}
├─ 报警时间：{alert.timestamp.isoformat()}
├─ 攻击IP：{alert.source_ip}
├─ 攻击类型：{alert.attack_type}
└─ 严重等级：{alert.severity.value}

【处置措施】
"""
        if rescue_task:
            for r in rescue_task.results:
                icon = "✅" if r.get("success") else "❌"
                report += f"{icon} {r.get('action')}\n"

        report += f"""
🔲 建议：人工复查并确认攻击是否造成实际影响
🔲 建议：更新 WAF 规则以防范同类攻击

==========================================
"""
        return report


# 全局单例
report_generator = ReportGenerator()
