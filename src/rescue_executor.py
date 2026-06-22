"""
救援执行器 (Member D)
通过 paramiko SSH 连接 Docker 容器，执行真实的救援命令
支持事务性执行：任一步骤失败则回滚
"""

import time
import threading
from datetime import datetime
from typing import Optional

import paramiko
import yaml
from pathlib import Path
from rich.console import Console

from src.models import RescueTask, RescueAction, Alert, Severity
from src.config import SSH_TARGET_PORT, SSH_USERNAME, SSH_PASSWORD, DOCKER_DIR

console = Console()


class RescueExecutor:
    """SSH 救援执行器"""

    def __init__(self):
        self.ssh: Optional[paramiko.SSHClient] = None
        self._load_playbooks()
        self._active_tasks: dict[str, RescueTask] = {}

    def _load_playbooks(self):
        """加载救援剧本"""
        playbook_path = Path(__file__).parent / "playbooks.yaml"
        with open(playbook_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        self.playbooks = config.get("playbooks", {})

    def _connect_ssh(self) -> bool:
        """建立 SSH 连接"""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                hostname="localhost",
                port=SSH_TARGET_PORT,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                timeout=10,
            )
            console.print("[green]✅ SSH 已连接到救援容器[/green]")
            return True
        except Exception as e:
            console.print(f"[red]❌ SSH 连接失败: {e}[/red]")
            return False

    def _disconnect_ssh(self):
        """断开 SSH 连接"""
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
            self.ssh = None

    def _execute_command(self, command: str, timeout: int = 10) -> dict:
        """执行单条命令"""
        result = {
            "command": command,
            "success": False,
            "output": "",
            "error": "",
            "exit_code": -1,
        }

        if not self.ssh:
            result["error"] = "SSH 未连接"
            return result

        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)
            result["exit_code"] = stdout.channel.recv_exit_status()
            result["output"] = stdout.read().decode("utf-8", errors="ignore").strip()
            result["error"] = stderr.read().decode("utf-8", errors="ignore").strip()
            result["success"] = result["exit_code"] == 0
        except Exception as e:
            result["error"] = str(e)

        return result

    def execute_rescue(self, alert: Alert) -> RescueTask:
        """根据告警执行对应的救援剧本"""
        task_id = f"RESCUE-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        # 查找匹配的救援剧本
        playbook = self._find_playbook(alert.attack_type)
        if not playbook:
            console.print(f"[yellow]⚠ 未找到攻击类型 '{alert.attack_type}' 的救援剧本[/yellow]")
            task = RescueTask(
                task_id=task_id,
                alert_id=alert.alert_id,
                attack_type=alert.attack_type,
                attacker_ip=alert.source_ip or "unknown",
                status="FAILED",
            )
            self._active_tasks[task_id] = task
            return task

        # 构建救援操作列表
        actions = []
        attacker_ip = alert.source_ip or "unknown"
        timestamp = datetime.now().isoformat()

        for action_def in playbook.get("actions", []):
            cmd = action_def["command"].format(
                attacker_ip=attacker_ip,
                timestamp=timestamp,
            )
            rollback_cmd = (
                action_def["rollback"].format(attacker_ip=attacker_ip, timestamp=timestamp)
                if action_def.get("rollback")
                else None
            )
            actions.append(RescueAction(
                name=action_def["name"],
                command=cmd,
                description=action_def.get("description", ""),
                rollback_command=rollback_cmd,
            ))

        task = RescueTask(
            task_id=task_id,
            alert_id=alert.alert_id,
            attack_type=alert.attack_type,
            attacker_ip=attacker_ip,
            actions=actions,
            status="PENDING",
        )

        console.print(f"\n[bold cyan]🚨 开始执行救援任务: {task_id}[/bold cyan]")
        console.print(f"   攻击类型: {alert.attack_type}")
        console.print(f"   攻击IP: {attacker_ip}")
        console.print(f"   操作步骤: {len(actions)} 步")

        # SSH 连接
        if not self._connect_ssh():
            task.status = "FAILED"
            self._active_tasks[task_id] = task
            return task

        # 顺序执行救援操作
        task.status = "RUNNING"
        executed_actions = []

        try:
            for i, action in enumerate(actions, 1):
                console.print(f"\n   [bold]{i}/{len(actions)}[/bold] {action.name}...")
                result = self._execute_command(action.command, timeout=10)

                task.results.append({
                    "action": action.name,
                    "command": action.command,
                    "success": result["success"],
                    "output": result["output"],
                    "error": result["error"],
                })
                executed_actions.append(action)

                if result["success"]:
                    console.print(f"   [green]✅ {action.name} 完成[/green]")
                else:
                    console.print(f"   [red]❌ {action.name} 失败: {result['error']}[/red]")

                    # 事务回滚：回滚已执行的操作
                    console.print(f"\n   [yellow]⏪ 执行回滚...[/yellow]")
                    for prev_action in reversed(executed_actions):
                        if prev_action.rollback_command:
                            rollback_result = self._execute_command(prev_action.rollback_command)
                            console.print(f"   回滚 {prev_action.name}: {'✅' if rollback_result['success'] else '❌'}")

                    task.status = "ROLLED_BACK"
                    break
            else:
                task.status = "SUCCESS"
                console.print(f"\n[bold green]✅ 救援任务完成[/bold green]")

        except Exception as e:
            console.print(f"[red]❌ 救援执行异常: {e}[/red]")
            task.status = "FAILED"
        finally:
            self._disconnect_ssh()

        self._active_tasks[task_id] = task
        return task

    def _find_playbook(self, attack_type: str) -> Optional[dict]:
        """根据攻击类型查找救援剧本"""
        # 精确匹配
        for key, pb in self.playbooks.items():
            if pb.get("attack_type") == attack_type:
                return pb
        # 模糊匹配
        for key, pb in self.playbooks.items():
            if attack_type in pb.get("attack_type", "") or pb.get("attack_type", "") in attack_type:
                return pb
        return None

    def get_task(self, task_id: str) -> Optional[RescueTask]:
        return self._active_tasks.get(task_id)

    def get_active_tasks(self) -> list[RescueTask]:
        return list(self._active_tasks.values())


# 全局单例
rescue_executor = RescueExecutor()
