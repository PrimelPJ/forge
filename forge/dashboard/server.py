"""Live ICS dashboard: process schematic, alerts feed, and asset inventory.

Serves the static HTML page and pushes updates over a WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from aiohttp import web, WSMsgType

from forge.events import Alert, EventBus
from forge.monitor.capture import TrafficMonitor
from forge.simulator.process import PlantState

log = logging.getLogger(__name__)

STATIC = Path(__file__).parent / "static"


class Dashboard:
    def __init__(
        self,
        plant: PlantState,
        bus: EventBus,
        monitor: TrafficMonitor,
        host: str = "0.0.0.0",
        port: int = 8080,
    ) -> None:
        self.plant = plant
        self.bus = bus
        self.monitor = monitor
        self.host = host
        self.port = port
        self._ws_clients: list[web.WebSocketResponse] = []

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/", self._index)
        app.router.add_get("/ws", self._websocket)
        app.router.add_static("/static", STATIC)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        asyncio.create_task(self._broadcast_loop())
        self.bus.subscribe(self._on_alert)
        log.info("Dashboard at http://%s:%d", self.host, self.port)

    async def _index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "index.html")

    async def _websocket(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self._ws_clients.append(ws)
        try:
            async for msg in ws:
                if msg.type == WSMsgType.CLOSE:
                    break
        finally:
            self._ws_clients.remove(ws)
        return ws

    async def _broadcast(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data)
        dead = []
        for ws in self._ws_clients:
            try:
                await ws.send_str(payload)
            except (ConnectionResetError, RuntimeError):
                dead.append(ws)
        for ws in dead:
            self._ws_clients.remove(ws)

    async def _broadcast_loop(self) -> None:
        while True:
            await self._broadcast({
                "type": "state",
                "plant": self.plant.snapshot(),
                "assets": self.monitor.asset_list(),
                "alert_count": len(self.bus.alerts),
            })
            await asyncio.sleep(1)

    async def _on_alert(self, alert: Alert) -> None:
        await self._broadcast({
            "type": "alert",
            "alert": alert.to_dict(),
        })
