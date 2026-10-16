"""Security event model and in-process pub/sub bus."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)


@dataclass
class Alert:
    """A security alert raised by the detection engine."""

    rule_id: str
    title: str
    severity: str  # critical, high, medium, low, info
    src_ip: str
    detail: str
    mitre_id: str
    mitre_tactic: str
    time: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrafficLog:
    """A single Modbus TCP transaction logged by the monitor."""

    src_ip: str
    src_port: int
    dst_port: int
    unit_id: int
    function_code: int
    is_write: bool
    address: int | None = None
    value: int | None = None
    time: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


Handler = Callable[[Alert], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=5000)
        self._handlers: list[Handler] = []
        self.alerts: list[Alert] = []

    def subscribe(self, handler: Handler) -> None:
        self._handlers.append(handler)

    def publish(self, alert: Alert) -> None:
        self.alerts.append(alert)
        try:
            self._queue.put_nowait(alert)
        except asyncio.QueueFull:
            pass

    async def run(self) -> None:
        while True:
            alert = await self._queue.get()
            for handler in self._handlers:
                try:
                    await handler(alert)
                except Exception:
                    log.exception("handler failed")
            self._queue.task_done()
