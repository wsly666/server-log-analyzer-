"""
Streamlit 主控台 (Member D)
实时日志流 | 告警列表 | 攻击模式切换 | 救援状态 | 报告预览 | 系统仪表盘
"""

import time
import threading
import asyncio
from datetime import datetime, timedelta
import sys
from pathlib import Path
from collections import deque

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import yaml

# 页面配置
st.set_page_config(
    page_title="AI-OPS 智能运维监控",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 导入所有模块
from src.log_simulator import LogSimulator
from src.attack_simulator import AttackSimulator
from src.log_monitor import LogMonitor
from src.rule_engine import RuleEngine
from src.llm_analyzer import LLMAnalyzer
from src.alert_manager import AlertManager
from src.rescue_executor import RescueExecutor
from src.report_generator import ReportGenerator
from src.chart_generator import (
    generate_error_trend_chart,
    generate_attack_pie_chart,
    generate_ip_bar_chart,
    generate_severity_bar_chart,
)
from src.email_sender import EmailSender
from src.log_rotator import rotate_log, get_rotation_info, manual_clear_log
from src.models import Alert, Severity
from src.config import ATTACK_CONFIG, LOG_MAX_SIZE_MB, LOG_ROTATE_KEEP, ALERT_DEDUP_WINDOW

# ============================================
# 自定义 CSS
# ============================================
st.markdown("""
<style>
    .critical-alert { border-left: 4px solid #c0392b; padding: 8px; background: #fdecea; margin: 4px 0; border-radius: 4px; }
    .high-alert { border-left: 4px solid #e74c3c; padding: 8px; background: #fef0ef; margin: 4px 0; border-radius: 4px; }
    .medium-alert { border-left: 4px solid #f39c12; padding: 8px; background: #fef9e7; margin: 4px 0; border-radius: 4px; }
    .low-alert { border-left: 4px solid #3498db; padding: 8px; background: #eaf2f8; margin: 4px 0; border-radius: 4px; }
    .status-ok { color: #27ae60; font-weight: bold; }
    .status-warn { color: #f39c12; font-weight: bold; }
    .status-critical { color: #c0392b; font-weight: bold; }
    .log-line { font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; padding: 2px 8px; border-bottom: 1px solid #f0f0f0; }
    .log-attack { background: #ffeaea; }
    .log-normal { background: #fafffe; }
</style>
""", unsafe_allow_html=True)

# ============================================
# 初始化全局单例
# ============================================
@st.cache_resource
def init_components():
    """初始化所有组件（缓存避免重复创建）"""
    return {
        "log_simulator": LogSimulator(),
        "attack_simulator": AttackSimulator(),
        "log_monitor": LogMonitor(),
        "rule_engine": RuleEngine(),
        "llm_analyzer": LLMAnalyzer(),
        "alert_manager": AlertManager(),
        "rescue_executor": RescueExecutor(),
        "report_generator": ReportGenerator(),
        "email_sender": EmailSender(),
    }


components = init_components()
log_sim = components["log_simulator"]
attack_sim = components["attack_simulator"]
log_mon = components["log_monitor"]
rule_eng = components["rule_engine"]
llm_analyzer = components["llm_analyzer"]
alert_mgr = components["alert_manager"]
rescue_exec = components["rescue_executor"]
report_gen = components["report_generator"]
email_sender = components["email_sender"]

# ============================================
# Session State 初始化
# ============================================
if "log_entries" not in st.session_state:
    st.session_state.log_entries = deque(maxlen=200)
if "alerts" not in st.session_state:
    st.session_state.alerts = deque(maxlen=100)
if "rescue_tasks" not in st.session_state:
    st.session_state.rescue_tasks = []
if "system_status" not in st.session_state:
    st.session_state.system_status = "normal"
if "normal_traffic_running" not in st.session_state:
    st.session_state.normal_traffic_running = False
if "attack_running" not in st.session_state:
    st.session_state.attack_running = False
if "report_content" not in st.session_state:
    st.session_state.report_content = ""
if "llm_cache" not in st.session_state:
    st.session_state.llm_cache = []
if "dedup_cache" not in st.session_state:
    st.session_state.dedup_cache = {}  # 去重缓存: {dedup_key: datetime}


# ============================================
# 辅助函数
# ============================================
def read_all_logs(log_key: str = "nginx_access") -> tuple[int, list[str]]:
    """读取日志文件：返回 (总行数, 所有行)"""
    from src.config import LOG_PATHS
    log_path = LOG_PATHS.get(log_key)
    if not log_path or not log_path.exists():
        return 0, []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = [l.strip() for l in f.readlines()]
            return len(all_lines), all_lines
    except Exception:
        return 0, []


def read_recent_logs(log_key: str = "nginx_access", lines: int = 50) -> list[str]:
    """读取最近的日志行（用于展示）"""
    _, all_lines = read_all_logs(log_key)
    return all_lines[-lines:] if all_lines else []


def _classify_attack_type_from_match(match) -> str:
    """从单个 RuleMatch 推断攻击类型"""
    name = match.rule_name
    if "SQL" in name:
        return "SQL注入扫描"
    elif "XSS" in name:
        return "XSS攻击"
    elif "暴力破解" in name:
        return "暴力破解"
    elif "路径" in name:
        return "路径遍历"
    elif "高频" in name:
        return "CC并发洪水"
    return "其他"


def _get_dominant_attack_types(matches: list) -> list[str]:
    """从规则匹配中提取所有显著攻击类型 (占比 >15%)

    重要：当存在具体攻击特征（SQL注入/XSS/暴力破解/路径遍历）时，
    排除"CC并发洪水"类型。因为任何自动化攻击都会产生高频请求，
    高频不应被误报为独立的 CC 洪水攻击。
    """
    from collections import Counter
    counts = Counter()
    for m in matches:
        t = _classify_attack_type_from_match(m)
        if t != "其他":
            counts[t] += 1

    # 如果检测到具体攻击特征，排除纯频率型的 CC 洪水
    specific_types = {"SQL注入扫描", "XSS攻击", "暴力破解", "路径遍历"}
    detected_specific = set(counts.keys()) & specific_types
    if detected_specific and "CC并发洪水" in counts:
        del counts["CC并发洪水"]

    total = sum(counts.values()) or 1
    return [t for t, c in counts.most_common() if c / total > 0.15]


def detect_attacks_in_logs(log_lines: list[str]):
    """对日志行运行检测引擎 —— 支持每批次多攻击类型独立告警"""
    from src.log_monitor import parse_nginx_access_line
    from src.models import LogEvent

    events = []
    for line in log_lines:
        event = parse_nginx_access_line(line)
        if event:
            events.append(event)

    print(f"[Detect] 收到 {len(log_lines)} 行日志, 解析出 {len(events)} 个事件")

    if not events:
        return

    # 规则引擎筛选 — 分析最近 1000 个事件 (覆盖多次攻击)
    suspicious_events = []
    all_matches = []
    for event in events[-1000:]:
        matches = rule_eng.analyze(event)
        if matches:
            suspicious_events.append(event)
            all_matches.extend(matches)

    print(f"[Detect] 规则引擎命中 {len(all_matches)} 条, 可疑事件 {len(suspicious_events)} 个")

    if not suspicious_events or len(suspicious_events) < 5:
        if suspicious_events:
            print(f"[Detect] ⚠ 可疑事件不足5个 ({len(suspicious_events)}), 不触发LLM分析")
        return

    # 识别批次中的多个攻击类型
    attack_types = _get_dominant_attack_types(all_matches)
    if not attack_types:
        attack_types = ["未知"]

    print(f"[Detect] 识别到攻击类型: {attack_types}")

    for attack_type in attack_types:
        # 按类型筛选可疑事件
        type_matches = [m for m in all_matches
                        if _classify_attack_type_from_match(m) == attack_type]

        # 对该类型事件单独做 LLM 分析
        # 筛选属于该类型的事件（其规则命中包含该类型）
        type_events = []
        for ev in suspicious_events:
            ev_matches = rule_eng.analyze(ev)  # 重新分析以获取该事件的匹配
            ev_types = {_classify_attack_type_from_match(m) for m in ev_matches}
            if attack_type in ev_types:
                type_events.append(ev)

        if len(type_events) < 5:
            print(f"[Detect] ⚠ {attack_type} 可疑事件不足5个 ({len(type_events)}), 跳过")
            continue

        # LLM 分析 (带缓存)
        cache_key = hash(tuple(e.raw_line for e in type_events[-20:]))
        if cache_key not in [c[0] for c in st.session_state.llm_cache]:
            with st.spinner(f"🧠 LLM 分析中 ({attack_type})..."):
                llm_result = llm_analyzer.analyze(type_events, type_matches)
            st.session_state.llm_cache.append((cache_key, llm_result))
            if len(st.session_state.llm_cache) > 20:
                st.session_state.llm_cache = st.session_state.llm_cache[-20:]
            print(f"[Detect] LLM分析完成 ({attack_type}): is_attack={llm_result.is_attack}, "
                  f"type={llm_result.attack_type}, severity={llm_result.severity}")
        else:
            for c in st.session_state.llm_cache:
                if c[0] == cache_key:
                    llm_result = c[1]
                    break
            else:
                llm_result = None
            print(f"[Detect] ({attack_type}) 命中LLM缓存")

        # 创建告警 (使用 session_state 管理的去重缓存)
        if llm_result and llm_result.is_attack:
            alert = alert_mgr.create_alert(
                type_events, type_matches, llm_result,
                dedup_cache=st.session_state.dedup_cache,
                dedup_window=ALERT_DEDUP_WINDOW,
            )
            if alert:
                st.session_state.alerts.appendleft(alert)
                st.session_state.system_status = "under_attack"
                print(f"[Detect] ✅ 告警创建成功: {alert.alert_id} | "
                      f"{alert.attack_type} | {alert.severity.value}")

                # 严重告警自动触发救援
                if alert.severity == Severity.CRITICAL:
                    rescue_task = rescue_exec.execute_rescue(alert)
                    st.session_state.rescue_tasks.append(rescue_task)
                    print(f"[Detect] 🚑 自动救援触发: {rescue_task.task_id}")
                    report = report_gen.generate(alert, rescue_task)
                    st.session_state.report_content = report
        else:
            print(f"[Detect] ⚠ {attack_type}: LLM判断非攻击或分析失败")


# ============================================
# 侧边栏
# ============================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("🛡️ AI-OPS")
    st.caption("服务器日志智能分析系统")

    st.divider()

    # 导航
    page = st.radio(
        "导航",
        ["📡 实时监控", "🚨 告警列表", "📊 分析报告", "📈 趋势图表", "⚙️ 系统设置"],
        label_visibility="collapsed",
    )

    st.divider()

    # 系统状态
    st.subheader("系统状态")
    status = st.session_state.system_status
    if status == "normal":
        st.success("🟢 系统正常")
    elif status == "under_attack":
        st.error("🔴 检测到攻击")
    elif status == "rescuing":
        st.warning("🟡 救援执行中")
    else:
        st.info("🔵 监控中")

    # 统计卡片
    col1, col2 = st.columns(2)
    with col1:
        st.metric("今日告警", len(st.session_state.alerts))
    with col2:
        active = sum(1 for a in st.session_state.alerts if a.status == "OPEN")
        st.metric("活跃告警", active)

    st.divider()

    # 攻击控制面板
    st.subheader("🎯 攻击模拟控制")

    # 正常流量开关
    if st.button(
        "⏹ 停止正常流量" if st.session_state.normal_traffic_running else "▶ 启动正常流量",
        width="stretch",
        type="secondary",
    ):
        if st.session_state.normal_traffic_running:
            log_sim.stop()
            st.session_state.normal_traffic_running = False
        else:
            log_sim.start()
            st.session_state.normal_traffic_running = True
        st.rerun()

    st.divider()
    st.caption("攻击模拟（选择一种）：")

    # 攻击按钮
    attack_buttons = {
        "💉 SQL注入扫描": "sql_injection",
        "⚠ XSS攻击": "xss",
        "🌊 CC并发洪水": "cc_flood",
        "🔓 暴力破解": "brute_force",
    }

    for label, atype in attack_buttons.items():
        if st.button(label, width="stretch"):
            attack_sim.launch_attack(atype)
            st.session_state.attack_running = True
            st.session_state.system_status = "under_attack"
            st.toast(f"🚨 {label} 已启动！", icon="🔥")
            time.sleep(1)
            st.rerun()

    st.divider()
    st.caption(f"© 2026 | v1.0 | DeepSeek AI")


# ============================================
# 主内容区
# ============================================

if page == "📡 实时监控":
    st.title("📡 实时日志监控")
    st.caption("Docker nginx 访问日志 — 实时滚动")

    # 自动刷新
    auto_refresh = st.checkbox("自动刷新 (每2秒)", value=True)

    # 日志展示区域
    log_container = st.empty()

    # 上次日志行数 (基于文件总行数)
    if "last_log_count" not in st.session_state:
        # 从当前文件行数开始，避免把历史日志当新数据重复检测
        st.session_state.last_log_count = read_all_logs("nginx_access")[0]

    # 读取日志：获取总行数 (用于增量检测) + 最近 100 行 (用于展示)
    total_count, all_lines = read_all_logs("nginx_access")
    log_lines = all_lines[-100:] if all_lines else []
    st.session_state.log_entries = deque(log_lines, maxlen=200)

    # 日志轮转检查 — 文件过大自动归档
    rotate_log("nginx_access")

    # 检测攻击 — 用总行数对比，传入整个新增区间
    if total_count > st.session_state.last_log_count:
        new_lines = all_lines[st.session_state.last_log_count:]
        print(f"[Monitor] 文件总行数: {total_count}, 上次: {st.session_state.last_log_count}, 新增: {len(new_lines)}")
        detect_attacks_in_logs(new_lines)
        st.session_state.last_log_count = total_count
    elif total_count < st.session_state.last_log_count:
        # 日志轮转：重置计数
        print(f"[Monitor] 检测到日志轮转 (总行 {total_count} < 上次 {st.session_state.last_log_count}), 重置计数")
        st.session_state.last_log_count = 0

    # 渲染日志
    with log_container:
        if log_lines:
            # 高亮攻击特征
            attack_keywords = [
                "OR '1'='1", "UNION SELECT", "DROP TABLE", "<script>",
                "onerror=", "javascript:", "../", "alert(",
            ]
            for line in reversed(log_lines[-50:]):
                is_attack_line = any(kw.lower() in line.lower() for kw in attack_keywords)
                css_class = "log-attack" if is_attack_line else "log-normal"
                st.markdown(
                    f'<div class="log-line {css_class}">{line[:200]}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.info("等待日志数据... 请先启动正常流量或攻击模拟。")

    # 自动刷新
    if auto_refresh:
        time.sleep(2)
        st.rerun()

elif page == "🚨 告警列表":
    st.title("🚨 告警列表")

    # 获取告警
    all_alerts = list(st.session_state.alerts)

    if not all_alerts:
        st.info("暂无告警记录。启动攻击模拟后将在此显示告警。")
    else:
        for alert in all_alerts:
            severity_emoji = {
                "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW": "🔵", "INFO": "⚪",
            }
            emoji = severity_emoji.get(alert.severity.value, "⚪")

            with st.expander(
                f"{emoji} [{alert.severity.value}] {alert.attack_type} | "
                f"IP: {alert.source_ip} | {alert.timestamp.strftime('%H:%M:%S')}",
                expanded=(alert.severity == Severity.CRITICAL),
            ):
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown(f"**告警ID**: `{alert.alert_id}`")
                    st.markdown(f"**时间**: {alert.timestamp.isoformat()}")
                    st.markdown(f"**严重等级**: {alert.severity.value}")
                    st.markdown(f"**攻击类型**: {alert.attack_type}")
                    st.markdown(f"**来源IP**: `{alert.source_ip}`")
                    st.markdown(f"**状态**: {alert.status}")
                    st.markdown(f"**自动救援**: {'✅ 已触发' if alert.auto_rescue_triggered else '❌ 未触发'}")

                with col2:
                    if alert.llm_analysis:
                        st.markdown("**🤖 LLM 分析结果**")
                        st.json({
                            "is_attack": alert.llm_analysis.is_attack,
                            "attack_type": alert.llm_analysis.attack_type,
                            "severity": alert.llm_analysis.severity,
                            "confidence": f"{alert.llm_analysis.confidence:.0%}",
                            "description": alert.llm_analysis.description[:200],
                            "recommendation": alert.llm_analysis.recommendation[:200],
                        })

                # 日志样本
                if alert.log_samples:
                    st.markdown("**📋 相关日志**")
                    for line in alert.log_samples[:10]:
                        st.code(line, language=None)

                # 操作按钮
                cols = st.columns(4)
                if alert.status == "OPEN":
                    with cols[0]:
                        if st.button("✅ 确认", key=f"ack_{alert.alert_id}"):
                            alert_mgr.acknowledge_alert(alert)
                            st.rerun()
                    with cols[1]:
                        if st.button("✅ 解决", key=f"res_{alert.alert_id}"):
                            alert_mgr.resolve_alert(alert)
                            st.rerun()
                if alert.severity in (Severity.CRITICAL, Severity.HIGH):
                    with cols[2]:
                        if st.button("🛡️ 手动救援", key=f"manres_{alert.alert_id}"):
                            with st.spinner("执行救援..."):
                                task = rescue_exec.execute_rescue(alert)
                                st.session_state.rescue_tasks.append(task)
                            st.rerun()
                    with cols[3]:
                        if st.button("📧 发送报告", key=f"email_{alert.alert_id}"):
                            with st.spinner("生成并发送报告..."):
                                report = report_gen.generate(alert)
                                email_sender.send_alert_email(alert, report, [])
                            st.success("报告已发送！")

elif page == "📊 分析报告":
    st.title("📊 分析报告")

    if st.session_state.report_content:
        st.markdown(st.session_state.report_content)
    else:
        st.info("暂无报告。当检测到攻击并执行救援后将自动生成报告。")

    # 历史报告
    st.divider()
    st.subheader("📁 历史报告")
    from src.config import REPORTS_DIR
    report_files = sorted(Path(REPORTS_DIR).glob("report_*.md"), reverse=True)
    if report_files:
        for rf in report_files[:10]:
            with st.expander(f"📄 {rf.name}"):
                content = rf.read_text(encoding="utf-8")
                st.markdown(content)
    else:
        st.caption("暂无历史报告")

elif page == "📈 趋势图表":
    st.title("📈 趋势图表")

    # ── 从真实日志计算请求频率趋势（每分钟请求数）──
    from src.log_monitor import parse_nginx_access_line
    from collections import Counter

    now = datetime.now()
    _, all_log_lines = read_all_logs("nginx_access")

    # 按分钟分桶统计所有请求
    request_buckets: dict[datetime, int] = {}
    for line in all_log_lines:
        event = parse_nginx_access_line(line)
        if event:
            minute_key = event.timestamp.replace(second=0, microsecond=0)
            request_buckets[minute_key] = request_buckets.get(minute_key, 0) + 1

    if request_buckets:
        sorted_times = sorted(request_buckets.keys())
        times = sorted_times
        errors = [request_buckets[t] for t in sorted_times]
    else:
        times = [now - timedelta(minutes=i) for i in range(60, 0, -1)]
        errors = [0] * 60

    # 从真实告警提取攻击标注
    attack_markers = []
    for alert in st.session_state.alerts:
        attack_markers.append({
            "time": alert.timestamp,
            "label": alert.attack_type,
        })

    # ── 从真实告警计算攻击分布 ──
    attack_counts = Counter()
    for alert in st.session_state.alerts:
        attack_counts[alert.attack_type] += 1
    if not attack_counts:
        attack_counts = {"暂无告警": 1}

    tab1, tab2, tab3 = st.tabs(["📉 请求趋势", "🥧 攻击分布", "📊 IP统计"])

    with tab1:
        st.subheader("请求频率趋势")
        st.caption(f"基于 {len(all_log_lines)} 条日志，{len(request_buckets)} 个时间桶")
        path = generate_error_trend_chart(
            times, errors,
            attack_markers=attack_markers if attack_markers else None,
        )
        st.image(path, width="stretch")

    with tab2:
        st.subheader("攻击类型分布")
        st.caption(f"共 {sum(attack_counts.values())} 条告警" if attack_counts.get("暂无告警", 0) == 0 else "等待攻击数据...")
        path = generate_attack_pie_chart(dict(attack_counts))
        st.image(path, width="stretch")

    with tab3:
        st.subheader("IP 请求量统计")
        st.caption("模拟演示数据（所有攻击来自同一IP，维持原状）")
        path = generate_ip_bar_chart({
            "192.168.1.5": 30, "192.168.1.6": 25, "192.168.1.7": 28,
            "10.0.0.100": 500, "192.168.1.9": 22,
        }, highlight_ip="10.0.0.100")
        st.image(path, width="stretch")

    # 救援任务历史
    st.divider()
    st.subheader("🛡️ 救援执行记录")
    if st.session_state.rescue_tasks:
        for task in st.session_state.rescue_tasks:
            with st.expander(
                f"{task.task_id} | {task.attack_type} | {task.status}",
            ):
                st.markdown(f"**IP**: `{task.attacker_ip}`")
                st.markdown(f"**状态**: {task.status}")
                for r in task.results:
                    icon = "✅" if r.get("success") else "❌"
                    st.markdown(f"{icon} `{r.get('action')}`: `{r.get('command', '')[:80]}`")
    else:
        st.caption("暂无救援记录")

elif page == "⚙️ 系统设置":
    st.title("⚙️ 系统设置")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔧 检测参数", "📧 邮件配置", "🤖 LLM配置", "📋 攻击参数", "📁 日志管理"])

    with tab1:
        st.subheader("规则引擎参数")
        st.slider("IP高频请求阈值 (次/分钟)", 10, 200, 30)
        st.slider("滑动窗口大小 (秒)", 10, 300, 60)
        st.slider("告警去重窗口 (秒)", 60, 1800, 300)

    with tab2:
        st.subheader("邮件 SMTP 配置")
        st.text_input("SMTP 服务器", value="smtp.qq.com", disabled=True)
        st.text_input("SMTP 端口", value="587", disabled=True)
        st.text_input("发件邮箱", type="password", placeholder="your-email@qq.com")
        st.text_input("授权码", type="password", placeholder="16位SMTP授权码")
        if st.button("📧 发送测试邮件"):
            with st.spinner("发送中..."):
                ok = email_sender.send_test_email()
            if ok:
                st.success("测试邮件发送成功！")
            else:
                st.error("发送失败，请检查配置")

    with tab3:
        st.subheader("LLM API 配置")
        st.text_input("API Base URL", value="https://api.deepseek.com", disabled=True)
        st.text_input("Model", value="deepseek-chat", disabled=True)
        st.slider("Temperature", 0.0, 1.0, 0.1)
        st.info("在 .env 文件中设置 LLM_API_KEY")

    with tab4:
        st.subheader("攻击模拟参数")
        st.json(ATTACK_CONFIG)

    with tab5:
        st.subheader("📁 日志文件管理")

        info = get_rotation_info("nginx_access")
        cols = st.columns(3)
        with cols[0]:
            st.metric("当前日志大小", f"{info['current_size_mb']:.1f} MB")
        with cols[1]:
            st.metric("自动轮转阈值", f"{info['max_size_mb']} MB")
        with cols[2]:
            st.metric("归档文件数", f"{info['rotated_count']} / {info['keep_count']}")

        # 轮转状态
        if info["rotated_files"]:
            st.markdown("**📦 归档列表**")
            for rf in info["rotated_files"]:
                st.markdown(f"- `{rf['name']}` ({rf['size_mb']} MB) — {rf['time']}")
            st.caption(f"归档总大小: {info['total_archived_mb']} MB")

        st.divider()

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🧹 手动清空日志", help="清空当前日志文件（不归档），用于开发调试"):
                if manual_clear_log("nginx_access"):
                    st.session_state.last_log_count = 0
                    st.session_state.dedup_cache.clear()
                    rule_eng.reset()
                    st.success("日志已清空，去重缓存已重置")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("清空失败")

        with col2:
            if st.button("🔄 强制轮转", help="立即归档当前日志并开始新文件"):
                archived = rotate_log("nginx_access", max_size_mb=0, keep=LOG_ROTATE_KEEP)
                if archived:
                    st.session_state.last_log_count = 0
                    st.session_state.dedup_cache.clear()
                    rule_eng.reset()
                    st.success(f"已归档到: {archived.name}，状态已重置")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.warning("轮转失败，请查看控制台")


# ============================================
# 页脚
# ============================================
st.divider()
cols = st.columns(4)
with cols[0]:
    st.metric("Docker 容器", "3", "running")
with cols[1]:
    st.metric("监控日志文件", "4", "active")
with cols[2]:
    st.metric("LLM 调用", len(st.session_state.llm_cache))
with cols[3]:
    st.metric("救援执行", len(st.session_state.rescue_tasks))

st.caption("🛡️ Server Log Intelligent Analyzer v1.0 | Powered by DeepSeek + LangChain | © 2026")

if __name__ == "__main__":
    # streamlit run src/app.py
    pass
