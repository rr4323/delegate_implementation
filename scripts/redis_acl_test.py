"""Validates Goal 8 from Delegate POC.md: Redis authenticates each delegate by
its own certificate, confines it to its own keys, and cuts it off on
revocation -- including an already-open connection.

Registers two throwaway delegates (A = attacker, B = victim) through the real
registration API, so each gets a real CA-signed cert and Redis ACL user, then
attacks Redis directly with A's cert. Exits non-zero if any check fails.

Usage: python scripts/redis_acl_test.py
Env:   CONTROL_PLANE_URL (default http://localhost:18000)
       REDIS_HOST / REDIS_PORT (default localhost / 16379)
"""
import os
import sys
import tempfile
import threading
import time
import uuid

import redis
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:18000")
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "16379"))
TENANT_A = "tenant-attacker"
TENANT_B = "tenant-victim"

FAILURES = []


def check(label: str, ok: bool, detail: str = ""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def denied(fn):
    """Runs fn and returns (True, error) if Redis refused it, else (False, result)."""
    try:
        return False, fn()
    except (redis.exceptions.NoPermissionError, redis.exceptions.AuthenticationError,
            redis.exceptions.ConnectionError, redis.exceptions.ResponseError, OSError) as exc:
        return True, f"{type(exc).__name__}: {str(exc)[:70]}"


class Delegate:
    def __init__(self, tenant_id: str, name: str, workdir: str):
        token = requests.post(f"{CONTROL_PLANE_URL}/api/registration-token/",
                              json={"tenant_id": tenant_id}, timeout=10).json()["token"]
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .sign(key, hashes.SHA256()))
        resp = requests.post(f"{CONTROL_PLANE_URL}/api/register/", json={
            "token": token, "tenant_id": tenant_id, "name": name, "queue": f"queue-{name}",
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        }, timeout=15)
        resp.raise_for_status()
        body = resp.json()
        self.tenant_id, self.name, self.id = tenant_id, name, body["delegate_id"]
        self.ca = os.path.join(workdir, f"{name}-ca.crt")
        self.cert = os.path.join(workdir, f"{name}.crt")
        self.key = os.path.join(workdir, f"{name}.key")
        open(self.ca, "w").write(body["ca_cert_pem"])
        open(self.cert, "w").write(body["cert_pem"])
        with open(self.key, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        self.prefix = f"delegate:{self.id}:"

    def redis(self, **kw):
        return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, ssl=True, ssl_ca_certs=self.ca,
                           ssl_certfile=self.cert, ssl_keyfile=self.key, ssl_cert_reqs="required",
                           ssl_check_hostname=True, decode_responses=True, socket_timeout=8, **kw)


def audit_events():
    return requests.get(f"{CONTROL_PLANE_URL}/api/audit-events/", timeout=10).json()["events"]


def main():
    workdir = tempfile.mkdtemp(prefix="redis-acl-test-")
    print(f"Registering delegates A (attacker, {TENANT_A}) and B (victim, {TENANT_B})...")
    a = Delegate(TENANT_A, f"acl-a-{uuid.uuid4().hex[:6]}", workdir)
    b = Delegate(TENANT_B, f"acl-b-{uuid.uuid4().hex[:6]}", workdir)
    print(f"  A={a.id}\n  B={b.id}")

    print("\n1. Connections without a valid client identity")
    no_cert = lambda: redis.Redis(host=REDIS_HOST, port=REDIS_PORT, ssl=True, ssl_ca_certs=a.ca,
                                  ssl_check_hostname=True, socket_timeout=8).ping()
    rejected, why = denied(no_cert)
    check("no client certificate is rejected at the TLS handshake", rejected, why)

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.id)])
    import datetime
    rogue = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
             .public_key(other_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=5))
             .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
             .sign(other_key, hashes.SHA256()))
    rogue_cert, rogue_key = os.path.join(workdir, "rogue.crt"), os.path.join(workdir, "rogue.key")
    open(rogue_cert, "wb").write(rogue.public_bytes(serialization.Encoding.PEM))
    open(rogue_key, "wb").write(other_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    rogue_conn = lambda: redis.Redis(host=REDIS_HOST, port=REDIS_PORT, ssl=True, ssl_ca_certs=a.ca,
                                     ssl_certfile=rogue_cert, ssl_keyfile=rogue_key,
                                     ssl_check_hostname=True, socket_timeout=8).ping()
    rejected, why = denied(rogue_conn)
    check("self-signed cert claiming A's CN (not signed by the CA) is rejected", rejected, why)

    print("\n2. Scope: A may only touch its own keys")
    ra = a.redis()
    check("A can XADD to its own stream", not denied(lambda: ra.xadd(f"{a.prefix}execution:x:events", {"k": "v"}))[0])
    rejected, why = denied(lambda: ra.xadd(f"{b.prefix}execution:x:events", {"k": "forged"}))
    check("A cannot XADD to B's stream", rejected, why)
    rejected, why = denied(lambda: ra.xread({f"{b.prefix}execution:x:events": "0"}, count=1))
    check("A cannot XREAD B's stream", rejected, why)
    rejected, why = denied(lambda: ra.xadd("execution:legacy:events", {"k": "v"}))
    check("A cannot write outside its prefix", rejected, why)
    for label, fn in [("KEYS *", lambda: ra.keys("*")), ("FLUSHALL", lambda: ra.flushall()),
                      ("ACL LIST", lambda: ra.execute_command("ACL", "LIST")),
                      ("CONFIG GET *", lambda: ra.config_get("*")),
                      ("GET on a foreign key", lambda: ra.get("anything"))]:
        rejected, why = denied(fn)
        check(f"A cannot run {label}", rejected, why)

    print("\n3. Global announcement stream is write-only for delegates")
    check("A can XADD to global:execution_events",
          not denied(lambda: ra.xadd("global:execution_events", {"type": "NOOP"}))[0])
    rejected, why = denied(lambda: ra.xread({"global:execution_events": "0"}, count=1))
    check("A cannot XREAD global:execution_events", rejected, why)

    print("\n4. Impersonation via AUTH is refused")
    for target in (b.id, "cp-admin", "default"):
        conn = a.redis()
        rejected, why = denied(lambda: conn.execute_command("AUTH", target, "anything"))
        check(f"A cannot AUTH as {target[:12]}", rejected, why)

    print("\n5. Forged EXECUTION_STARTED cannot redirect the dispatcher")
    exec_resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": TENANT_B, "delegate_id": b.id, "workspace_fixture": "sample_workspace"}, timeout=10)
    exec_id = exec_resp.json()["execution_id"]  # B has no worker, so its task just sits queued
    forged_events = f"{a.prefix}execution:{exec_id}:events"
    ra.xadd("global:execution_events", {
        "type": "EXECUTION_STARTED", "execution_id": exec_id, "events_stream": forged_events,
        "log_stream": f"{a.prefix}l", "status_stream": f"{a.prefix}s", "output_stream": f"{a.prefix}o"})
    ra.xadd(forged_events, {"type": "DATA_REQUEST", "execution_id": exec_id, "tenant_id": TENANT_B,
                            "delegate_id": b.id, "requested_file": "*"})
    mismatch = False
    for _ in range(15):
        mismatch = any(e["event_type"] == "ANNOUNCEMENT_STREAM_MISMATCH" and e["execution_id"] == exec_id
                       for e in audit_events())
        if mismatch:
            break
        time.sleep(1)
    check("dispatcher audits the announcement/DB stream-name mismatch", mismatch)
    time.sleep(2)
    resp = ra.xread({forged_events: "0"}, count=100)
    replies = [f["type"] for _stream, msgs in resp for _id, f in msgs
               if f.get("type", "").startswith("DATA_") and f["type"] != "DATA_REQUEST"]
    check("dispatcher sent no workspace data onto A's forged stream", not replies, str(replies))

    print("\n6. Revocation cuts off new AND already-open connections")
    live = a.redis()
    live.xadd(f"{a.prefix}live", {"k": "v"})
    outcome = {}

    def blocked_read():
        conn = a.redis()
        conn.connection_pool.connection_kwargs["socket_timeout"] = 30
        started = time.time()
        try:
            conn.xread({f"{a.prefix}blocked": "$"}, block=25000)
            outcome["result"] = "returned normally"
        except Exception as exc:
            outcome["result"] = f"{type(exc).__name__}"
        outcome["seconds"] = time.time() - started

    t = threading.Thread(target=blocked_read)
    t.start()
    time.sleep(1.5)
    rev = requests.post(f"{CONTROL_PLANE_URL}/api/delegates/{a.id}/revoke/", timeout=20).json()
    check("revoke API reports the Redis ACL user was removed", rev.get("redis_acl_removed") is True, str(rev))
    t.join(timeout=10)
    check("A's blocked XREAD (open connection) was terminated promptly",
          outcome.get("result") == "ConnectionError" and outcome.get("seconds", 99) < 8, str(outcome))
    rejected, why = denied(lambda: live.xadd(f"{a.prefix}live", {"k": "after-revoke"}))
    check("A's other open connection can no longer write", rejected, why)
    rejected, why = denied(lambda: a.redis().xadd(f"{a.prefix}live", {"k": "new-conn"}))
    check("a NEW connection with A's still-valid cert is refused", rejected, why)
    check("audit log records REDIS_ACL_REVOKED", any(
        e["event_type"] == "REDIS_ACL_REVOKED" and e["delegate_id"] == a.id for e in audit_events()))
    task_resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": TENANT_A, "delegate_id": a.id, "workspace_fixture": "sample_workspace"}, timeout=10)
    check("control plane refuses new tasks for the revoked delegate", task_resp.status_code == 403,
          f"HTTP {task_resp.status_code}")
    check("victim B is unaffected by A's revocation", not denied(lambda: b.redis().xadd(f"{b.prefix}ok", {"k": "v"}))[0])

    print()
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} check(s) failed: {FAILURES}")
        sys.exit(1)
    print("PASS: Redis identity, scope and revocation behave as designed")


if __name__ == "__main__":
    main()
