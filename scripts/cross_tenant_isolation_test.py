"""Validates Goal 7 from Delegate POC.md: a delegate belonging to one tenant
must not be able to pull another tenant's execution workspace.

Registers a second delegate under a different tenant and, using *its own*
real cert, tries to forge a DATA_REQUEST onto the victim delegate's
execution stream. Redis' per-delegate ACL (Goal 8) refuses the write outright,
so the forged request never reaches the control plane. (The dispatcher's own
tenant/delegate ownership check in `_handle_data_request` is the inner layer;
it can no longer be reached from outside, since only the assigned delegate can
write to its execution's streams.) Finally confirms the victim's legitimate
execution is unaffected and completes.

Usage: python scripts/cross_tenant_isolation_test.py
Env:   CONTROL_PLANE_URL, REDIS_HOST, REDIS_PORT (see redis_acl_test.py)
"""
import os
import sys
import tempfile
import time

import redis
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:18000")
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "16379"))
TENANT_DEMO = "tenant-demo"
TENANT_OTHER = "tenant-attacker"


def _register_delegate(tenant_id: str, name: str):
    """Returns (delegate_id, redis_client authenticated with the delegate's own cert)."""
    token = requests.post(f"{CONTROL_PLANE_URL}/api/registration-token/",
                           json={"tenant_id": tenant_id}, timeout=10).json()["token"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{tenant_id}:{name}")]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    resp = requests.post(f"{CONTROL_PLANE_URL}/api/register/", json={
        "token": token, "tenant_id": tenant_id, "name": name, "csr_pem": csr_pem,
    }, timeout=10)
    resp.raise_for_status()
    body = resp.json()
    d = tempfile.mkdtemp(prefix="isolation-test-")
    paths = {n: os.path.join(d, n) for n in ("ca.crt", "delegate.crt", "delegate.key")}
    open(paths["ca.crt"], "w").write(body["ca_cert_pem"])
    open(paths["delegate.crt"], "w").write(body["cert_pem"])
    with open(paths["delegate.key"], "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, ssl=True, ssl_ca_certs=paths["ca.crt"],
                         ssl_certfile=paths["delegate.crt"], ssl_keyfile=paths["delegate.key"],
                         ssl_check_hostname=True, decode_responses=True, socket_timeout=8)
    return body["delegate_id"], client


def _get_delegate_id_for_demo_tenant() -> str:
    resp = requests.get(f"{CONTROL_PLANE_URL}/api/audit-events/", timeout=10)
    for event in resp.json()["events"]:
        if event["event_type"] == "DELEGATE_REGISTERED" and "name=vm-delegate-1" in event["detail"]:
            return event["delegate_id"]
    raise RuntimeError("vm-delegate-1 not registered yet")


def main():
    print(f"Registering attacker delegate under tenant={TENANT_OTHER}...")
    attacker_delegate_id, r = _register_delegate(TENANT_OTHER, "attacker-delegate")
    print(f"attacker_delegate_id={attacker_delegate_id}")

    victim_delegate_id = None
    for _ in range(30):
        try:
            victim_delegate_id = _get_delegate_id_for_demo_tenant()
            break
        except RuntimeError:
            time.sleep(2)
    if not victim_delegate_id:
        print("FAIL: could not find tenant-demo's registered delegate")
        sys.exit(1)

    resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": TENANT_DEMO, "delegate_id": victim_delegate_id, "workspace_fixture": "sample_workspace",
    }, timeout=10)
    resp.raise_for_status()
    execution_id = resp.json()["execution_id"]
    print(f"victim execution_id={execution_id}")

    events_key = f"delegate:{victim_delegate_id}:execution:{execution_id}:events"

    print("Attacker (its own valid cert) forges a DATA_REQUEST onto the victim's execution stream...")
    try:
        r.xadd(events_key, {
            "type": "DATA_REQUEST", "execution_id": execution_id,
            "tenant_id": TENANT_OTHER, "delegate_id": attacker_delegate_id, "paths": "*",
        })
        print("FAIL: Redis accepted a write to another delegate's stream")
        sys.exit(1)
    except redis.exceptions.NoPermissionError as exc:
        print(f"  refused by Redis ACL: {exc}")
    try:
        r.xread({events_key: "0"}, count=1)
        print("FAIL: Redis let the attacker read another delegate's stream")
        sys.exit(1)
    except redis.exceptions.NoPermissionError as exc:
        print(f"  read refused by Redis ACL: {exc}")

    print("Checking the victim's own execution is unaffected...")
    status = None
    for _ in range(60):
        body = requests.get(f"{CONTROL_PLANE_URL}/api/executions/{execution_id}/", timeout=10).json()
        status = body["status"]
        if status in {"SUCCEEDED", "FAILED", "TRANSFER_FAILED"}:
            break
        time.sleep(1)
    if status != "SUCCEEDED":
        print(f"FAIL: victim execution ended in status={status}")
        sys.exit(1)

    print("PASS: cross-tenant forgery was refused at Redis and the victim's execution completed")


if __name__ == "__main__":
    main()
