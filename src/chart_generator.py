"""
图表生成器 (Member D)
使用 matplotlib 生成趋势图/饼图/柱状图，pillow 进行后期处理和标注
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib
matplotlib.use("Agg")  # 非交互式后端

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator
from PIL import Image, ImageDraw, ImageFont

from src.config import CHARTS_DIR

# ============================================
# 中文字体配置
# ============================================
plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False


def _save_and_annotate(fig, filename: str, watermark: str = "AI-OPS"):
    """保存图表并用 pillow 添加水印"""
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = CHARTS_DIR / filename

    # 保存 matplotlib 图表
    fig.savefig(filepath, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)

    # pillow 添加水印和时间标注
    try:
        img = Image.open(filepath)
        draw = ImageDraw.Draw(img)

        # 右下角水印
        text = f"{watermark} | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        bbox = draw.textbbox((0, 0), text)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        x = img.width - text_width - 15
        y = img.height - text_height - 10

        # 半透明背景
        overlay = Image.new("RGBA", img.size, (255, 255, 255, 0))
        overlay_draw = ImageDraw.Draw(overlay)
        overlay_draw.rectangle(
            [x - 5, y - 2, x + text_width + 5, y + text_height + 4],
            fill=(255, 255, 255, 180)
        )
        img = Image.alpha_composite(img.convert("RGBA"), overlay)
        draw = ImageDraw.Draw(img)
        draw.text((x, y), text, fill=(100, 100, 100))
        img = img.convert("RGB")
        img.save(filepath)
    except Exception:
        pass

    return str(filepath)


def generate_error_trend_chart(
    timestamps: list[datetime],
    error_counts: list[int],
    attack_markers: Optional[list[dict]] = None,
) -> str:
    """
    生成错误频率折线图
    :param timestamps: X轴时间列表
    :param error_counts: Y轴错误数量列表
    :param attack_markers: 攻击标注 [{time, label}]
    """
    fig, ax = plt.subplots(figsize=(10, 4))

    ax.plot(timestamps, error_counts, color="#1a73e8", linewidth=1.5, marker="o", markersize=3)
    ax.fill_between(timestamps, error_counts, alpha=0.1, color="#1a73e8")

    # 标注攻击爆发点
    if attack_markers:
        for marker in attack_markers:
            ax.axvline(x=marker["time"], color="red", linestyle="--", alpha=0.7, linewidth=1)
            ax.annotate(
                marker["label"],
                xy=(marker["time"], max(error_counts) * 0.9),
                fontsize=8,
                color="red",
                fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffeeee", alpha=0.8),
            )

    ax.set_xlabel("时间", fontsize=10)
    ax.set_ylabel("请求数量", fontsize=10)
    ax.set_title("服务器请求频率趋势", fontsize=13, fontweight="bold")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.xaxis.set_major_locator(MaxNLocator(8))
    plt.xticks(rotation=30)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()

    return _save_and_annotate(fig, "error_trend.png")


def generate_attack_pie_chart(attack_stats: dict[str, int]) -> str:
    """
    生成攻击类型饼图
    :param attack_stats: {攻击类型: 数量}
    """
    fig, ax = plt.subplots(figsize=(7, 5))

    labels = list(attack_stats.keys())
    sizes = list(attack_stats.values())
    colors = ["#e74c3c", "#e67e22", "#f1c40f", "#3498db", "#9b59b6"]
    explode = [0.05] * len(labels)

    wedges, texts, autotexts = ax.pie(
        sizes,
        explode=explode,
        labels=labels,
        colors=colors[:len(labels)],
        autopct="%1.1f%%",
        startangle=140,
        textprops={"fontsize": 9},
    )
    for at in autotexts:
        at.set_fontweight("bold")

    ax.set_title("攻击类型分布", fontsize=13, fontweight="bold")
    plt.tight_layout()

    return _save_and_annotate(fig, "attack_pie.png")


def generate_ip_bar_chart(ip_stats: dict[str, int], highlight_ip: Optional[str] = None) -> str:
    """
    生成 IP 请求量对比柱状图
    :param ip_stats: {IP: 请求量}
    :param highlight_ip: 需要高亮的攻击IP
    """
    fig, ax = plt.subplots(figsize=(10, 4))

    ips = list(ip_stats.keys())
    counts = list(ip_stats.values())
    bar_colors = ["#e74c3c" if ip == highlight_ip else "#3498db" for ip in ips]

    bars = ax.bar(range(len(ips)), counts, color=bar_colors, edgecolor="white")
    ax.set_xticks(range(len(ips)))
    ax.set_xticklabels(ips, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("请求数量", fontsize=10)
    ax.set_title("IP 请求量统计", fontsize=13, fontweight="bold")

    # 在柱上标数值
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                str(count), ha="center", fontsize=8)

    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    return _save_and_annotate(fig, "ip_stats.png")


def generate_severity_bar_chart(severity_counts: dict[str, int]) -> str:
    """
    生成告警严重等级柱状图
    """
    fig, ax = plt.subplots(figsize=(6, 4))

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    labels = [o for o in order if o in severity_counts]
    counts = [severity_counts.get(o, 0) for o in labels]
    colors = ["#c0392b", "#e74c3c", "#f39c12", "#3498db", "#95a5a6"]

    ax.bar(labels, counts, color=colors[:len(labels)], edgecolor="white")
    ax.set_ylabel("告警数量", fontsize=10)
    ax.set_title("告警严重等级分布", fontsize=13, fontweight="bold")
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))

    for i, count in enumerate(counts):
        if count > 0:
            ax.text(i, count + 0.5, str(count), ha="center", fontweight="bold")

    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    return _save_and_annotate(fig, "severity_stats.png")


if __name__ == "__main__":
    # 测试图表生成
    from datetime import timedelta

    now = datetime.now()
    times = [now - timedelta(minutes=i * 5) for i in range(20, 0, -1)]
    errors = [0, 1, 0, 2, 1, 0, 3, 1, 0, 2, 15, 30, 25, 12, 5, 2, 1, 0, 1, 0]

    path = generate_error_trend_chart(
        times, errors,
        attack_markers=[{"time": times[10], "label": "SQL注入攻击爆发"}]
    )
    print(f"趋势图: {path}")

    path2 = generate_attack_pie_chart({
        "SQL注入扫描": 45, "XSS攻击": 12, "CC洪水": 30, "暴力破解": 8, "正常": 5
    })
    print(f"饼图: {path2}")

    path3 = generate_ip_bar_chart({
        "192.168.1.5": 30, "192.168.1.6": 25, "192.168.1.7": 28,
        "10.0.0.100": 500, "192.168.1.9": 22
    }, highlight_ip="10.0.0.100")
    print(f"柱状图: {path3}")
