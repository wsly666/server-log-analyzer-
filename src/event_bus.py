"""
模块间异步事件总线
实现松耦合的消息传递：日志监控 → 检测引擎 → 救援执行器
"""

import asyncio
import json
from datetime import datetime
from typing import Callable, Optional
from collections import deque

from src.models import EventBusMessage


class EventBus:
    """简易异步事件总线"""

    def __init__(self, max_queue_size: int = 1000):
        self._subscribers: dict[str, list[Callable]] = {}
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._event_history: deque = deque(maxlen=500)
        self._running = False

    def subscribe(self, event_type: str, handler: Callable):
        """订阅事件"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    async def publish(self, msg: EventBusMessage):
        """发布事件"""
        self._event_history.append(msg)
        try:
            self._queue.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    async def start(self):
        """启动事件分发循环"""
        self._running = True
        while self._running:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                handlers = self._subscribers.get(msg.event_type, [])
                for handler in handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(msg)
                        else:
                            handler(msg)
                    except Exception as e:
                        print(f"[EventBus] Handler error for {msg.event_type}: {e}")
            except asyncio.TimeoutError:
                continue

    def stop(self):
        """停止事件循环"""
        self._running = False

    def get_recent_events(self, event_type: Optional[str] = None, limit: int = 50) -> list[EventBusMessage]:
        """获取最近的事件"""
        events = list(self._event_history)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]


# 全局单例
event_bus = EventBus()
