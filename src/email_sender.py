"""
邮件发送模块 (Member D)
使用 smtplib 发送分析报告 + 图表附件
支持 HTML 格式和内嵌图片
"""

import smtplib
import base64
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime

from src.models import Alert
from src.config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL,
    CHARTS_DIR, REPORTS_DIR,
)


class EmailSender:
    """邮件发送器"""

    def __init__(self):
        self.smtp_host = SMTP_HOST
        self.smtp_port = SMTP_PORT
        self.smtp_user = SMTP_USER
        self.smtp_password = SMTP_PASSWORD
        self.alert_email = ALERT_EMAIL

    def send_alert_email(self, alert: Alert, report_md: str,
                         chart_paths: list[str] = None) -> bool:
        """
        发送告警邮件
        :param alert: 告警对象
        :param report_md: Markdown 格式报告
        :param chart_paths: 图表文件路径列表
        """
        try:
            # 构建邮件
            msg = MIMEMultipart("related")
            subject = f"[{alert.severity.value}] 安全告警 - {alert.attack_type} - {alert.source_ip}"
            msg["Subject"] = subject
            msg["From"] = f"AI-OPS <{self.smtp_user}>"
            msg["To"] = self.alert_email
            msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0800")

            # HTML 正文
            html_body = self._build_html_body(alert, report_md, chart_paths)
            msg_alt = MIMEMultipart("alternative")
            msg.attach(msg_alt)
            msg_alt.attach(MIMEText(html_body, "html", "utf-8"))

            # 附件：Markdown 报告
            report_attachment = MIMEText(report_md, "plain", "utf-8")
            report_attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=f"report_{alert.alert_id}.md"
            )
            msg.attach(report_attachment)

            # 附件：图表（内嵌到HTML中）
            if chart_paths:
                for i, chart_path in enumerate(chart_paths):
                    if Path(chart_path).exists():
                        with open(chart_path, "rb") as f:
                            img_data = f.read()
                        img = MIMEImage(img_data)
                        img.add_header("Content-ID", f"<chart_{i}>")
                        img.add_header(
                            "Content-Disposition",
                            "inline",
                            filename=Path(chart_path).name
                        )
                        msg.attach(img)

            # 发送
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            print(f"[EmailSender] ✅ 邮件已发送: {subject}")
            return True

        except smtplib.SMTPAuthenticationError:
            print("[EmailSender] ❌ SMTP 认证失败，请检查邮箱授权码")
            return False
        except smtplib.SMTPConnectError:
            print("[EmailSender] ❌ SMTP 连接失败，请检查网络和服务器地址")
            return False
        except smtplib.SMTPSenderRefused:
            print("[EmailSender] ❌ 发件人被拒绝")
            return False
        except Exception as e:
            print(f"[EmailSender] ❌ 发送失败: {e}")
            return False

    def _build_html_body(self, alert: Alert, report_md: str,
                         chart_paths: list[str] = None) -> str:
        """构建 HTML 邮件正文"""

        severity_color = {
            "CRITICAL": "#c0392b", "HIGH": "#e74c3c",
            "MEDIUM": "#f39c12", "LOW": "#3498db", "INFO": "#95a5a6",
        }
        color = severity_color.get(alert.severity.value, "#333")

        # 将 markdown 报告转为简单 HTML
        report_html = report_md.replace("\n", "<br>")

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 700px; margin: 0 auto;">
    <div style="background: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
        <h1 style="margin: 0;">🚨 {alert.severity.value} 安全告警</h1>
        <p style="margin: 8px 0 0;">{alert.attack_type} | 攻击IP: {alert.source_ip}</p>
    </div>
    <div style="background: #fafafa; padding: 20px; border: 1px solid #eee;">
        <table style="width: 100%; border-collapse: collapse;">
            <tr><td style="padding: 8px; color: #666;">告警ID</td><td><code>{alert.alert_id}</code></td></tr>
            <tr><td style="padding: 8px; color: #666;">时间</td><td>{alert.timestamp.isoformat()}</td></tr>
            <tr><td style="padding: 8px; color: #666;">严重等级</td><td style="color: {color}; font-weight: bold;">{alert.severity.value}</td></tr>
            <tr><td style="padding: 8px; color: #666;">攻击类型</td><td>{alert.attack_type}</td></tr>
            <tr><td style="padding: 8px; color: #666;">攻击IP</td><td><code>{alert.source_ip}</code></td></tr>
            <tr><td style="padding: 8px; color: #666;">自动救援</td><td>{'✅ 已触发' if alert.auto_rescue_triggered else '⚠ 未触发'}</td></tr>
        </table>
    </div>
"""
        # 内嵌图表
        if chart_paths:
            for i, path in enumerate(chart_paths):
                if Path(path).exists():
                    html += f"""
    <div style="margin-top: 16px; text-align: center;">
        <img src="cid:chart_{i}" style="max-width: 100%; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    </div>"""

        html += f"""
    <div style="background: white; padding: 20px; margin-top: 16px; border-radius: 8px; border: 1px solid #eee;">
        <h3>📋 分析报告</h3>
        <pre style="white-space: pre-wrap; font-family: inherit; color: #333;">{report_html}</pre>
    </div>
    <div style="color: #999; font-size: 12px; text-align: center; margin-top: 20px; padding: 16px;">
        <p>此邮件由 AI-OPS 智能运维系统自动发送</p>
        <p>🛡️ Server Log Intelligent Analyzer | {datetime.now().year}</p>
    </div>
</body>
</html>"""
        return html

    def send_test_email(self) -> bool:
        """发送测试邮件验证配置"""
        html = """<h2>✅ AI-OPS 邮件配置测试</h2><p>如果您收到此邮件，说明 SMTP 配置正确。</p>"""
        msg = MIMEMultipart()
        msg["Subject"] = "AI-OPS 邮件测试"
        msg["From"] = self.smtp_user
        msg["To"] = self.alert_email
        msg.attach(MIMEText(html, "html", "utf-8"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            print("[EmailSender] ✅ 测试邮件发送成功")
            return True
        except Exception as e:
            print(f"[EmailSender] ❌ 测试邮件发送失败: {e}")
            return False


# 全局单例
email_sender = EmailSender()
