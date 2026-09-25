"""Validates task-queue isolation -- a layer redis_acl_test.py doesn't cover.

That script tests the delegate protocol's own streams (events/log/status/
output). This one tests Celery's *broker* keys instead: when the control
plane assigns an execution to delegate V, Celery/kombu enqueues the task as
a Redis list at `delegate:<V>:<V's queue name>` (confirmed by hand against a
live stack: it's a plain Redis LIST holding the serialized task message, plus
a `_kombu.binding.<queue>` set kombu uses for routing). A rogue delegate R,
with its own perfectly valid cert and ACL user, must not be able to:
  - read/steal V's queued task (would let R execute work meant for V, in V's
    tenant, using V's assigned workspace/output paths)
  - inject a forged message onto V's queue (would let R get arbitrary code
    executed as if the control plane had assigned it to V)
while R's *own* queue continues to work normally, and revocation removes R's
access to even its own queue (not just the protocol streams).

This does NOT require any Celery worker to be running -- it inspects the
raw Redis list kombu creates, the same way an attacker would have to.

Usage: python scripts/rogue_task_execution_test.py
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

FAILURES = []


def check(label: str, ok: bool, detail: str = ""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def denied(fn):
    try:
        return False, fn()
    except (redis.exceptions.NoPermissionError, redis.exceptions.AuthenticationError,
            redis.exceptions.ConnectionError, redis.exceptions.ResponseError, OSError) as exc:
        return True, f"{type(exc).__name__}: {str(exc)[:70]}"


class Delegate:
    """Registers through the real API (own tenant, own CA-signed cert, own
    Celery queue name) -- same pattern as redis_acl_test.py, but this one
    also picks its own `queue` so the two delegates' queue *names* differ
    (their Redis *keys* would stay isolated either way, via the delegate
    prefix, even with identical queue names -- picking different names here
    just keeps the printed keys easy to tell apart)."""

    def __init__(self, tenant_id: str, name: str, queue: str, workdir: str):
        token = requests.post(f"{CONTROL_PLANE_URL}/api/registration-token/",
                              json={"tenant_id": tenant_id}, timeout=10).json()["token"]
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .sign(key, hashes.SHA256()))
        resp = requests.post(f"{CONTROL_PLANE_URL}/api/register/", json={
            "token": token, "tenant_id": tenant_id, "name": name, "queue": queue,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
        }, timeout=15)
        resp.raise_for_status()
        body = resp.json()
        self.tenant_id, self.name, self.queue, self.id = tenant_id, name, queue, body["delegate_id"]
        self.ca = os.path.join(workdir, f"{name}-ca.crt")
        self.cert = os.path.join(workdir, f"{name}.crt")
        self.key = os.path.join(workdir, f"{name}.key")
        open(self.ca, "w").write(body["ca_cert_pem"])
        open(self.cert, "w").write(body["cert_pem"])
        with open(self.key, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        self.prefix = f"delegate:{self.id}:"
        self.queue_key = f"{self.prefix}{self.queue}"
        self.binding_key = f"{self.prefix}_kombu.binding.{self.queue}"

    def redis(self, **kw):
        return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, ssl=True, ssl_ca_certs=self.ca,
                           ssl_certfile=self.cert, ssl_keyfile=self.key, ssl_cert_reqs="required",
                           ssl_check_hostname=True, decode_responses=True, socket_timeout=8, **kw)


def create_execution(tenant_id: str, delegate_id: str):
    resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": tenant_id, "delegate_id": delegate_id, "workspace_fixture": "sample_workspace",
    }, timeout=10)
    resp.raise_for_status()
    return resp.json()["execution_id"]


def main():
    workdir = tempfile.mkdtemp(prefix="rogue-task-test-")
    print("Registering victim and rogue delegates (different tenants, different queue names)...")
    v = Delegate("tenant-victim", f"task-victim-{os.getpid()}", "queue-victim", workdir)
    r_deleg = Delegate("tenant-rogue", f"task-rogue-{os.getpid()}", "queue-rogue", workdir)
    print(f"  victim={v.id} queue_key={v.queue_key}")
    print(f"  rogue ={r_deleg.id} queue_key={r_deleg.queue_key}")

    print("\n1. Control plane enqueues a real task for the victim (no worker needs to be running)")
    exec_id = create_execution(v.tenant_id, v.id)
    time.sleep(0.5)  # give Celery's own send_task a moment to LPUSH
    vconn = v.redis()
    queued = vconn.lrange(v.queue_key, 0, -1)
    check("victim's own cert can see its queued task (sanity: it really landed)",
          len(queued) == 1 and exec_id in queued[0], f"{len(queued)} message(s)")

    print("\n2. Rogue (its own valid cert) attacks the victim's queue key directly")
    rconn = r_deleg.redis()
    rejected, why = denied(lambda: rconn.lrange(v.queue_key, 0, -1))
    check("rogue cannot LRANGE (read/steal) the victim's queued task", rejected, why)
    rejected, why = denied(lambda: rconn.brpop([v.queue_key], timeout=1))
    check("rogue cannot BRPOP (dequeue/steal) the victim's queued task", rejected, why)
    rejected, why = denied(lambda: rconn.lpush(v.queue_key, "forged-task-body"))
    check("rogue cannot LPUSH (inject) a forged task onto the victim's queue", rejected, why)
    rejected, why = denied(lambda: rconn.smembers(v.binding_key))
    check("rogue cannot read the victim's kombu binding key", rejected, why)
    rejected, why = denied(lambda: rconn.llen(v.queue_key))
    check("rogue cannot even LLEN the victim's queue (existence-probe denied too)", rejected, why)

    # confirm the attack attempts didn't corrupt or consume the real message
    still_there = vconn.lrange(v.queue_key, 0, -1)
    check("victim's task is untouched after the attack attempts", still_there == queued, str(still_there))

    print("\n3. Rogue's OWN queue still works normally (ACL isn't overly restrictive)")
    rogue_exec_id = create_execution(r_deleg.tenant_id, r_deleg.id)
    time.sleep(0.5)
    check("rogue can read its own queued task",
          not denied(lambda: rconn.lrange(r_deleg.queue_key, 0, -1))[0])
    own = rconn.lrange(r_deleg.queue_key, 0, -1)
    check("rogue's own task is really its own", len(own) == 1 and rogue_exec_id in own[0])
    check("rogue can dequeue (BRPOP) its own task, same as its real Celery worker would",
          not denied(lambda: rconn.brpop([r_deleg.queue_key], timeout=2))[0])

    print("\n4. Revocation removes queue access too, not just the protocol streams")
    rev = requests.post(f"{CONTROL_PLANE_URL}/api/delegates/{r_deleg.id}/revoke/", timeout=20).json()
    check("revoke API reports the ACL user was removed", rev.get("redis_acl_removed") is True, str(rev))
    rejected, why = denied(lambda: r_deleg.redis().lrange(r_deleg.queue_key, 0, -1))
    check("revoked rogue can no longer read even its own queue", rejected, why)

    print("\nCleanup: revoking the victim test delegate too")
    requests.post(f"{CONTROL_PLANE_URL}/api/delegates/{v.id}/revoke/", timeout=20)

    print()
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} check(s) failed: {FAILURES}")
        sys.exit(1)
    print("PASS: Celery task-queue keys are isolated per delegate, same as the protocol streams")


if __name__ == "__main__":
    main()
