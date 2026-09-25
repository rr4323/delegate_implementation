"""Redis is TLS-only and authenticates the delegate by its own client
certificate (CN -> ACL user), so point the shared Redis client at the same
cert directory registration writes to. Runs before anything opens a Redis
connection; explicit REDIS_TLS_* env vars still win.
"""
import os

_cert_dir = os.environ.get("CERT_DIR", "/app/certs")
os.environ.setdefault("REDIS_TLS_CA", os.path.join(_cert_dir, "ca.crt"))
os.environ.setdefault("REDIS_TLS_CERT", os.path.join(_cert_dir, "delegate.crt"))
os.environ.setdefault("REDIS_TLS_KEY", os.path.join(_cert_dir, "delegate.key"))
