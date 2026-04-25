"""
dashboard_server_ai.py - WebSocket + HTTP Server for the AI-Enhanced Security Dashboard

Serves dashboard_ai.html over HTTP and pushes live events to the browser
via WebSocket. Extends dashboard_server.py with AI anomaly support.
"""

import asyncio
import websockets
import json
import threading
import time
from typing import Set
import logging
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
import webbrowser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - DASHBOARD - %(message)s"
)
logger = logging.getLogger(__name__)


class DashboardServer:
    """WebSocket server that pushes MQTT events to the browser dashboard."""

    def __init__(self, ws_port=8765, http_port=8000):
        self.ws_port = ws_port
        self.http_port = http_port
        self.connected_clients: Set = set()
        self._loop = None
        self.stats = {
            "total": 0,
            "valid": 0,
            "rejected": 0,
            "ai_anomalies": 0
        }

    # -----------------------------------------------------------------
    # WebSocket client management
    # -----------------------------------------------------------------
    async def register_client(self, websocket):
        self.connected_clients.add(websocket)
        logger.info(f"Dashboard client connected. Total clients: {len(self.connected_clients)}")
        await self._send(websocket, {
            "type": "stats_update",
            "data": self.stats
        })

    async def unregister_client(self, websocket):
        self.connected_clients.discard(websocket)
        logger.info(f"Dashboard client disconnected. Total clients: {len(self.connected_clients)}")

    async def _send(self, websocket, message):
        try:
            await websocket.send(json.dumps(message))
        except websockets.exceptions.ConnectionClosed:
            await self.unregister_client(websocket)
        except Exception as e:
            logger.error(f"Error sending to client: {e}")

    async def broadcast(self, message):
        if not self.connected_clients:
            return
        disconnected = set()
        for ws in self.connected_clients.copy():
            try:
                await ws.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(ws)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                disconnected.add(ws)
        for ws in disconnected:
            self.connected_clients.discard(ws)

    async def handle_client(self, websocket):
        await self.register_client(websocket)
        try:
            async for raw in websocket:
                try:
                    data = json.loads(raw)
                    if data.get("type") == "ping":
                        await self._send(websocket, {"type": "pong"})
                except json.JSONDecodeError:
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister_client(websocket)

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------
    def log_valid_message(self, device_id, sensor_data, topic=""):
        """Called when a message passes all rule-based checks."""
        self.stats["total"] += 1
        self.stats["valid"] += 1

        message = {
            "type": "valid_message",
            "data": {
                "device_id": device_id,
                "topic": topic,
                "timestamp": time.strftime("%H:%M:%S"),
                "pressure_psi": sensor_data.get("pressure_upstream",
                                sensor_data.get("pressure_psi", 0)),
                "flow_rate_gpm": sensor_data.get("flow_rate",
                                 sensor_data.get("flow_rate_gpm", 0)),
                "valve_position": sensor_data.get("gate_a_position",
                                  sensor_data.get("valve_position", 50)),
                "zone": self._zone_from_topic(topic)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"Valid message from {device_id}")

    def log_rejected_message(self, reason, attack_type, source, topic=""):
        """Called when a message fails rule-based validation."""
        self.stats["total"] += 1
        self.stats["rejected"] += 1

        message = {
            "type": "attack",
            "data": {
                "attack_type": attack_type,
                "source": source,
                "topic": topic,
                "reasons": [reason],
                "timestamp": time.strftime("%H:%M:%S"),
                "description": self._describe_attack(attack_type)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"REJECTED: {attack_type} from {source}")

    def log_ai_anomaly(self, device_id, sensor_data, ai_score, topic=""):
        """Called when AI model flags an anomaly that passed all rule checks."""
        self.stats["total"] += 1
        self.stats["ai_anomalies"] += 1

        message = {
            "type": "ai_anomaly",
            "data": {
                "device_id": device_id,
                "topic": topic,
                "timestamp": time.strftime("%H:%M:%S"),
                "ai_score": round(ai_score, 3),
                "anomaly_description": "Unusual sensor pattern detected by AI",
                "pressure_psi": sensor_data.get("pressure_upstream",
                                sensor_data.get("pressure_psi", 0)),
                "flow_rate_lpm": sensor_data.get("flow_rate",
                                 sensor_data.get("flow_rate_gpm", 0)),
                "valve_position": sensor_data.get("gate_a_position",
                                  sensor_data.get("valve_position", 50)),
                "zone": self._zone_from_topic(topic)
            }
        }
        self._schedule_broadcast(message)
        logger.info(f"AI ANOMALY: score={ai_score:.3f} from {device_id}")

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    def _schedule_broadcast(self, message):
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast(message), self._loop
            )
        except Exception as e:
            logger.error(f"Failed to broadcast: {e}")

    @staticmethod
    def _zone_from_topic(topic):
        if "device-002" in topic:
            return "pool_spa"
        if "device-003" in topic:
            return "kitchen"
        return "main_building"

    @staticmethod
    def _describe_attack(attack_type):
        descriptions = {
            "Message Tampering":  "HMAC mismatch — message contents were altered",
            "Replay Attack":      "Sequence number already seen — duplicate message blocked",
            "Stale Message":      "Timestamp too old — message outside freshness window",
            "Missing Fields":     "Required security fields absent from message",
        }
        return descriptions.get(attack_type, "Security violation detected")

    # -----------------------------------------------------------------
    # Server startup
    # -----------------------------------------------------------------
    def _start_websocket_server(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def serve():
            async with websockets.serve(self.handle_client, "localhost", self.ws_port):
                logger.info(f"WebSocket server running on ws://localhost:{self.ws_port}")
                await asyncio.Future()

        loop.run_until_complete(serve())

    def _start_http_server(self):
        serve_dir = os.path.dirname(os.path.abspath(__file__))

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=serve_dir, **kwargs)

            def do_GET(self):
                if self.path in ("/", "/dashboard"):
                    self.path = "/dashboard_ai.html"
                super().do_GET()

            def log_message(self, fmt, *args):
                pass

        server = HTTPServer(("localhost", self.http_port), Handler)
        logger.info(f"HTTP server running on http://localhost:{self.http_port}")
        server.serve_forever()

    def start(self, open_browser=True):
        """Start both HTTP and WebSocket servers."""
        logger.info("Starting Dashboard Server...")

        http_thread = threading.Thread(target=self._start_http_server, daemon=True)
        http_thread.start()

        if open_browser:
            time.sleep(0.5)
            webbrowser.open(f"http://localhost:{self.http_port}")

        self._start_websocket_server()


if __name__ == "__main__":
    server = DashboardServer()
    server.start(open_browser=True)