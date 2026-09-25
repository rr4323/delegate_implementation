"""Redis connection helpers. Redis is TLS-only and requires a client
certificate: the certificate's CN selects the ACL user (Redis
`tls-auth-clients-user CN`), so a delegate authenticates with its own
CA-issued cert and the control plane with its `cp-admin` cert. No password is
sent by clients (the ACL users have random, undistributed passwords so nobody
can `AUTH` as another user).

Cert paths come from the environment, so the same code serves the worker
(delegate cert) and the control plane (admin cert):
  REDIS_TLS_CA, REDIS_TLS_CERT, REDIS_TLS_KEY
If none are set (plain `redis://` URL) the connection is unencrypted -- only
intended for throwaway local experiments.
"""
import os
import ssl

import redis


def _tls_paths():
    # These three names are generic on purpose (this module is shared code),
    # so REDIS_TLS_CERT/KEY do NOT always point at the same file: for a
    # worker they resolve to delegate.crt/.key (set in worker_app/__init__.py),
    # for the control plane/dispatcher to redis_admin.crt/.key (set in
    # docker-compose.yml / local-run/env.sh). Same var names, different
    # identity, depending on who is running this process.
    ca = os.environ.get("REDIS_TLS_CA")
    cert = os.environ.get("REDIS_TLS_CERT")
    key = os.environ.get("REDIS_TLS_KEY")
    if ca and cert and key:
        return ca, cert, key
    return None


def get_redis(url: str) -> redis.Redis:
    kwargs = {"decode_responses": True}
    paths = _tls_paths()
    if url.startswith("rediss://") and paths:
        ca, cert, key = paths
        kwargs.update(
            ssl_ca_certs=ca, ssl_certfile=cert, ssl_keyfile=key,
            ssl_cert_reqs="required", ssl_check_hostname=True,
        )
    return redis.Redis.from_url(url, **kwargs)


def broker_ssl_options():
    """`broker_use_ssl` value for Celery/kombu, or None for a plain broker."""
    paths = _tls_paths()
    if not paths:
        return None
    ca, cert, key = paths
    return {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_ca_certs": ca, "ssl_certfile": cert, "ssl_keyfile": key,
    }
