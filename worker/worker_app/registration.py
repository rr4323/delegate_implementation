"""Delegate registration: registration-token -> local keypair -> CSR ->
CA-signed certificate, exactly as described in Delegate Design.md's
"Delegate Authentication and Authorization" section. The private key is
generated here and never leaves this process.
"""
import json
import os
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_DIR = os.environ.get("CERT_DIR", "/app/certs")


def _generate_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_csr_pem(key, common_name: str) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _wait_for_control_plane(base_url: str, timeout: float = 60) -> None:
    print(f"[registration] waiting for control plane at {base_url} to become reachable...")
    deadline = time.time() + timeout
    last_progress_print = 0.0
    while time.time() < deadline:
        try:
            requests.get(f"{base_url}/api/audit-events/", timeout=2)
            print(f"[registration] control plane at {base_url} is reachable")
            return
        except requests.RequestException as exc:
            now = time.time()
            if now - last_progress_print >= 5:
                print(f"[registration] still waiting for {base_url} ({exc.__class__.__name__}); retrying...")
                last_progress_print = now
            time.sleep(1)
    raise RuntimeError(f"control plane at {base_url} did not become ready in time")


def register(control_plane_url: str, tenant_id: str, name: str, queue: str, concurrency: int) -> dict:
    os.makedirs(CERT_DIR, exist_ok=True)
    identity_path = os.path.join(CERT_DIR, "identity.json")
    key_path = os.path.join(CERT_DIR, "delegate.key")
    cert_path = os.path.join(CERT_DIR, "delegate.crt")
    ca_path = os.path.join(CERT_DIR, "ca.crt")

    if os.path.exists(identity_path) and os.path.exists(cert_path):
        with open(identity_path) as f:
            identity = json.load(f)
        print(f"[registration] found existing identity in {CERT_DIR}, reusing it "
              f"(delete that directory to force re-registration): delegate_id={identity['delegate_id']}")
        return identity

    print(f"[registration] no existing identity in {CERT_DIR}; registering fresh as "
          f"tenant={tenant_id} name={name!r} against {control_plane_url}")

    _wait_for_control_plane(control_plane_url)

    # NOTE: in production, issuing the registration token is a separate,
    # authenticated admin action. This POC's control plane intentionally
    # leaves that endpoint open so `docker compose up` can self-register a
    # demo delegate without a manual step -- see views.issue_registration_token.
    print(f"[registration] POST {control_plane_url}/api/registration-token/ (tenant_id={tenant_id})")
    token_resp = requests.post(
        f"{control_plane_url}/api/registration-token/", json={"tenant_id": tenant_id}, timeout=10,
    )
    token_resp.raise_for_status()
    token = token_resp.json()["token"]
    print("[registration] registration token received")

    print("[registration] generating local RSA keypair and CSR (private key stays on this delegate)")
    key = _generate_keypair()
    csr_pem = _build_csr_pem(key, common_name=f"{tenant_id}:{name}")

    print(f"[registration] POST {control_plane_url}/api/register/ (submitting CSR for signing)")
    reg_resp = requests.post(f"{control_plane_url}/api/register/", json={
        "token": token, "tenant_id": tenant_id, "name": name,
        "queue": queue, "concurrency": concurrency, "csr_pem": csr_pem,
    }, timeout=10)
    reg_resp.raise_for_status()
    body = reg_resp.json()
    print(f"[registration] CA-signed certificate received (delegate_id={body['delegate_id']}); writing to {CERT_DIR}")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    with open(cert_path, "w") as f:
        f.write(body["cert_pem"])
    with open(ca_path, "w") as f:
        f.write(body["ca_cert_pem"])

    identity = {
        "delegate_id": body["delegate_id"],
        "tenant_id": tenant_id,
        "name": name,
        "queue": queue,
        "cert_expires_at": body["cert_expires_at"],
    }
    with open(identity_path, "w") as f:
        json.dump(identity, f)

    print(f"[registration] registered delegate_id={identity['delegate_id']} tenant={tenant_id} (mTLS cert issued)")
    return identity
