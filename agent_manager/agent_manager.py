"""Stand-in for `agent_manager`, per Delegate Design.md's "Agent restart"
section. It runs on the same machine as the delegate and manages its restarts:
it makes an *outbound* mTLS websocket connection to the control plane's
restart gateway, waits for a RESTART command, and restarts the delegate.

It authenticates with the delegate's own client certificate (same machine,
same identity), read from a read-only mount of the delegate's cert directory,
so the control plane knows which delegate this connection speaks for.

The VM-vs-Kubernetes difference lives entirely in `restart_delegate()`; here
the "machine" is a compose sidecar and the delegate is a sibling container.
"""
import asyncio
import json
import os
import ssl

import docker
import websockets

# NOTE: CERT_DIR here means something different than it does in the worker.
# The worker's CERT_DIR is its OWN identity; this CERT_DIR is a read-only
# mount of that SAME worker's cert directory (docker-compose.yml mounts the
# same *_certs volume into both containers) -- agent_manager has no identity
# of its own, it borrows the delegate's, since "same machine, same identity"
# (see module docstring above).
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
GATEWAY_URL = os.environ.get("CONTROL_PLANE_WS_URL", "wss://restart_gateway:8765")
DELEGATE_COMPOSE_SERVICE = os.environ["DELEGATE_COMPOSE_SERVICE"]


def restart_delegate():
    client = docker.from_env()
    containers = client.containers.list(
        all=True, filters={"label": f"com.docker.compose.service={DELEGATE_COMPOSE_SERVICE}"},
    )
    if not containers:
        raise RuntimeError(f"no container found for compose service {DELEGATE_COMPOSE_SERVICE!r}")
    for container in containers:
        print(f"[agent_manager] restarting delegate container {container.name}")
        container.restart(timeout=10)


async def run():
    with open(os.path.join(CERT_DIR, "identity.json")) as f:
        identity = json.load(f)

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(os.path.join(CERT_DIR, "ca.crt"))
    ssl_context.load_cert_chain(
        os.path.join(CERT_DIR, "delegate.crt"), os.path.join(CERT_DIR, "delegate.key"),
    )

    while True:
        try:
            async with websockets.connect(GATEWAY_URL, ssl=ssl_context) as ws:
                await ws.send(json.dumps({"type": "HELLO", "delegate_id": identity["delegate_id"]}))
                print(f"[agent_manager] connected to control plane as delegate {identity['delegate_id']}")
                async for message in ws:
                    if json.loads(message).get("type") == "RESTART":
                        print("[agent_manager] RESTART command received")
                        await asyncio.to_thread(restart_delegate)
        except Exception as exc:
            print(f"[agent_manager] connection lost/failed: {exc}; retrying in 3s")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(run())
