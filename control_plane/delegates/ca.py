"""Minimal local CA: issues the root CA once, then signs delegate client
certificates and the control plane's own server certificate off it. Real mTLS
handshakes -- not a simulation -- validated with Python's stdlib `ssl` module
by the restart gateway (control plane side) and agent_manager (delegate side).
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings

CA_KEY_PATH = lambda: os.path.join(settings.CA_DIR, "ca.key")
CA_CERT_PATH = lambda: os.path.join(settings.CA_DIR, "ca.crt")
# Distinct from the earlier "server.key/.crt" (issued for agent_manager) so a
# persisted CA volume from that layout regenerates a cert with the right SAN.
# "Server" here means the restart-channel websocket (control_plane HTTP API +
# restart_gateway), NOT Redis -- see REDIS_SERVER_*_PATH below for Redis's own,
# unrelated server cert. Two different services, both happen to be "servers."
SERVER_KEY_PATH = lambda: os.path.join(settings.CA_DIR, "control_plane_server.key")
SERVER_CERT_PATH = lambda: os.path.join(settings.CA_DIR, "control_plane_server.crt")

def _san_entry(name: str):
    """A SAN entry for `name`, as an IPAddress if it parses as one, else a
    DNSName. TLS hostname verification (ssl_check_hostname=True, on every
    client in this codebase) only accepts a connection if the hostname it
    dialed appears in the presented cert's SAN list -- so reaching a server
    cert by a name/IP not in its SAN list fails the handshake even though the
    cert chain itself is perfectly valid. See settings.REDIS_EXTRA_SAN_NAMES /
    CONTROL_PLANE_EXTRA_SAN_NAMES for how to add the address a real remote
    deployment is actually reached at."""
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


# Hostnames delegates' agent_managers may use to reach the restart gateway.
# settings.CONTROL_PLANE_EXTRA_SAN_NAMES (env CONTROL_PLANE_EXTRA_SAN_NAMES,
# comma-separated) adds names/IPs for when this isn't reached only inside the
# compose network -- e.g. a remote deployment's public IP or DNS name.
CONTROL_PLANE_SERVER_NAMES = ("restart_gateway", "control_plane", "localhost", *settings.CONTROL_PLANE_EXTRA_SAN_NAMES)

# Redis is TLS-only and requires client certs from this CA. Its server cert,
# and the control plane's own client cert (CN == the Redis ACL user
# `cp-admin`, see redis/entrypoint.sh) are issued here.
REDIS_SERVER_KEY_PATH = lambda: os.path.join(settings.CA_DIR, "redis_server.key")
REDIS_SERVER_CERT_PATH = lambda: os.path.join(settings.CA_DIR, "redis_server.crt")
# Filename says "redis_admin" (it's the file the control plane/dispatcher use
# to talk TO Redis), but the identity actually baked into its CN is
# REDIS_ADMIN_USER below, "cp-admin" -- that CN is what Redis's ACL/
# tls-auth-clients-user actually sees and keys off, not this filename.
REDIS_ADMIN_KEY_PATH = lambda: os.path.join(settings.CA_DIR, "redis_admin.key")
REDIS_ADMIN_CERT_PATH = lambda: os.path.join(settings.CA_DIR, "redis_admin.crt")
# settings.REDIS_EXTRA_SAN_NAMES (env REDIS_EXTRA_SAN_NAMES, comma-separated
# names/IPs) -- same reasoning as CONTROL_PLANE_EXTRA_SAN_NAMES above, for
# whatever address a worker actually uses in its REDIS_URL when it isn't just
# reaching Redis by its in-compose-network name.
REDIS_SERVER_NAMES = ("redis", "localhost", *settings.REDIS_EXTRA_SAN_NAMES)
REDIS_ADMIN_USER = "cp-admin"  # the CN baked into REDIS_ADMIN_CERT_PATH's cert, i.e. its Redis ACL username


def _write_private_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def _write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def ensure_root_ca():
    """Generates the root CA keypair/cert on first run; no-op afterwards."""
    if os.path.exists(CA_KEY_PATH()) and os.path.exists(CA_CERT_PATH()):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "BuildPiper Delegate POC Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BuildPiper POC"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private_key(CA_KEY_PATH(), key)
    _write_cert(CA_CERT_PATH(), cert)


def ca_cert_pem() -> str:
    with open(CA_CERT_PATH()) as f:
        return f.read()


def _load_ca():
    with open(CA_KEY_PATH(), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH(), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def sign_csr(csr_pem: str, common_name: str, validity_days: int) -> tuple:
    """Signs a CSR with the root CA. Returns (cert_pem, serial_hex, not_valid_after)."""
    ensure_root_ca()
    ca_key, ca_cert = _load_ca()
    csr = x509.load_pem_x509_csr(csr_pem.encode())

    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_after = now + datetime.timedelta(days=validity_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_valid_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, format(cert.serial_number, "x"), not_valid_after


def ensure_control_plane_server_cert():
    """Issues the control plane's server cert, once. agent_manager dials out to
    the restart gateway and verifies this cert; the gateway in turn verifies
    agent_manager's client cert, which is the delegate's own (see sign_csr).
    """
    ensure_root_ca()
    if os.path.exists(SERVER_KEY_PATH()) and os.path.exists(SERVER_CERT_PATH()):
        return

    ca_key, ca_cert = _load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    san = x509.SubjectAlternativeName([_san_entry(n) for n in CONTROL_PLANE_SERVER_NAMES])
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "control_plane")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write_private_key(SERVER_KEY_PATH(), key)
    _write_cert(SERVER_CERT_PATH(), cert)


def _issue_leaf_cert(key_path, cert_path, common_name, eku, san_names=()):
    """Issues a long-lived leaf cert off the root CA, once (no-op if both
    files already exist). Used for infrastructure certs, not delegates."""
    ensure_root_ca()
    if os.path.exists(key_path) and os.path.exists(cert_path):
        return

    ca_key, ca_cert = _load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    )
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san_entry(n) for n in san_names]), critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    _write_private_key(key_path, key)
    _write_cert(cert_path, cert)


def ensure_redis_server_cert():
    _issue_leaf_cert(
        REDIS_SERVER_KEY_PATH(), REDIS_SERVER_CERT_PATH(), "redis",
        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, REDIS_SERVER_NAMES,
    )


def ensure_redis_admin_client_cert():
    """Client cert the control plane/dispatcher present to Redis. Its CN is
    the ACL user name, so Redis maps it to `cp-admin` without a password."""
    _issue_leaf_cert(
        REDIS_ADMIN_KEY_PATH(), REDIS_ADMIN_CERT_PATH(), REDIS_ADMIN_USER,
        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
    )
