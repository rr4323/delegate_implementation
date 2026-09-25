"""Control-plane side of the agent restart channel, per Delegate Design.md's
"Agent restart" section: each delegate's `agent_manager` makes an *outbound*
mTLS websocket connection here and waits; this process pushes a RESTART
command down it, and agent_manager restarts the delegate on its own machine.

agent_manager authenticates with the delegate's own client certificate (same
machine, same identity), so the delegate_id is read from the TLS-verified
peer cert's CN rather than trusted from the HELLO message. Also exposes a tiny
HTTP control endpoint so operators/test scripts can trigger a restart.
"""
import asyncio
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import websockets
from django.core.management.base import BaseCommand

from delegates import ca
from delegates.models import AuditEvent, Delegate

WS_PORT = 8765
CONTROL_PORT = 8766

CONNECTED = {}


def _peer_cert_delegate_id(websocket):
    peercert = websocket.transport.get_extra_info("peercert")
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _lookup_active_delegate(delegate_id):
    try:
        return Delegate.objects.filter(id=delegate_id, status=Delegate.STATUS_ACTIVE).first()
    except Exception:  # CN that isn't a valid UUID
        return None


def _audit(event_type, delegate, detail=""):
    AuditEvent.objects.create(
        event_type=event_type, tenant_id=delegate.tenant_id, delegate_id=str(delegate.id), detail=detail,
    )


async def handler(websocket):
    delegate_id = None
    cert_delegate_id = _peer_cert_delegate_id(websocket)
    try:
        async for message in websocket:
            data = json.loads(message)
            if data.get("type") != "HELLO":
                continue
            claimed_id = data.get("delegate_id")
            if not cert_delegate_id or claimed_id != cert_delegate_id:
                print(
                    f"[restart_gateway] rejecting HELLO: claimed delegate_id={claimed_id!r} "
                    f"does not match client certificate CN={cert_delegate_id!r}"
                )
                await websocket.close(code=4001, reason="delegate_id does not match client certificate")
                return
            delegate = await asyncio.to_thread(_lookup_active_delegate, claimed_id)
            if delegate is None:
                print(f"[restart_gateway] rejecting HELLO: delegate {claimed_id!r} unknown or revoked")
                await websocket.close(code=4003, reason="delegate unknown or revoked")
                return
            delegate_id = claimed_id
            CONNECTED[delegate_id] = websocket
            print(f"[restart_gateway] agent_manager for delegate {delegate_id} connected (cert-verified)")
    finally:
        if delegate_id and CONNECTED.get(delegate_id) is websocket:
            CONNECTED.pop(delegate_id, None)
            print(f"[restart_gateway] agent_manager for delegate {delegate_id} disconnected")


async def send_restart(delegate_id: str) -> bool:
    ws = CONNECTED.get(delegate_id)
    if ws is None:
        return False
    await ws.send(json.dumps({"type": "RESTART"}))
    delegate = await asyncio.to_thread(_lookup_active_delegate, delegate_id)
    if delegate is not None:
        await asyncio.to_thread(_audit, "DELEGATE_RESTART_SENT", delegate)
    return True


async def disconnect(delegate_id: str) -> bool:
    """Closes a delegate's open restart-channel websocket (used on revocation,
    so a revoked delegate can't keep an already-established channel alive)."""
    ws = CONNECTED.pop(delegate_id, None)
    if ws is None:
        return False
    await ws.close(code=4003, reason="delegate revoked")
    return True


def make_control_handler(loop):
    class ControlHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            if self.path == "/connected":
                body = json.dumps({"connected": list(CONNECTED.keys())}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            if self.path.startswith("/restart/"):
                delegate_id = self.path.split("/restart/", 1)[1]
                future = asyncio.run_coroutine_threadsafe(send_restart(delegate_id), loop)
                sent = future.result(timeout=5)
                self.send_response(200 if sent else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"sent": sent}).encode())
                return
            if self.path.startswith("/disconnect/"):
                delegate_id = self.path.split("/disconnect/", 1)[1]
                future = asyncio.run_coroutine_threadsafe(disconnect(delegate_id), loop)
                closed = future.result(timeout=5)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"disconnected": closed}).encode())
                return
            self.send_response(404)
            self.end_headers()

    return ControlHandler


async def serve():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(ca.SERVER_CERT_PATH(), ca.SERVER_KEY_PATH())
    ssl_context.load_verify_locations(ca.CA_CERT_PATH())
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # mTLS: reject any client without a CA-signed cert

    loop = asyncio.get_running_loop()
    control_server = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), make_control_handler(loop))
    threading.Thread(target=control_server.serve_forever, daemon=True).start()
    print(f"[restart_gateway] control HTTP API listening on :{CONTROL_PORT}")

    async with websockets.serve(handler, "0.0.0.0", WS_PORT, ssl=ssl_context):
        print(f"[restart_gateway] mTLS websocket listening on :{WS_PORT} (client certs required)")
        await asyncio.Future()


class Command(BaseCommand):
    help = "Accepts agent_manager's outbound mTLS websocket connections and pushes RESTART commands down them."

    def handle(self, *args, **options):
        ca.ensure_root_ca()
        ca.ensure_control_plane_server_cert()
        asyncio.run(serve())
