"""Redis ACL lifecycle for delegates.

Redis is TLS-only with client certs, and maps the certificate CN to an ACL
user (`tls-auth-clients-user CN`). A delegate's cert CN is its delegate_id
(set at registration, see views.register_delegate), so each delegate gets an
ACL user named after its id that can touch only `delegate:<id>:*` -- its own
execution streams and, via kombu's `global_keyprefix`, its own Celery broker
keys -- plus write-only access to the global announcement stream.

Verified against Redis 8.6.6 (see README, "Redis access control"):
- the `default` user must be off, otherwise a valid cert whose CN has no ACL
  user silently connects as `default` (redis/entrypoint.sh seeds it off);
- ACL users must NOT be `nopass`: any cert holder could `AUTH <that user> x`
  and become it. Each user gets a random password that is never stored or
  handed out -- the cert-to-user mapping needs no password;
- `ACL DELUSER` also terminates that user's open connections (including a
  blocked XREAD), unlike `ACL SETUSER ... off`, which only blocks new logins.
"""
import logging
import re
import secrets

from django.conf import settings

from delegate_protocol.redis_client import get_redis
from delegate_protocol.streams import GLOBAL_EXECUTION_EVENTS_STREAM, delegate_prefix

logger = logging.getLogger(__name__)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Minimal command set a delegate needs: our stream protocol (XADD/XREAD) plus
# what Celery/kombu's Redis transport uses (found by restricting a user and
# reading ACL LOG denials until the worker ran cleanly). Deliberately no @all,
# no @dangerous, no ACL/CONFIG/KEYS/FLUSH*.
DELEGATE_COMMANDS = (
    "xadd", "xread",
    "brpop", "lpush", "rpush", "llen", "lrange", "lpop", "rpop", "lrem",
    "zadd", "zrem", "zrangebyscore", "zrevrangebyscore",
    "hset", "hget", "hdel", "hgetall", "hexists",
    "sadd", "srem", "smembers",
    "set", "get", "evalsha", "script|load", "del", "exists", "expire",
    "multi", "exec", "discard", "watch", "unwatch",
    "publish", "subscribe", "psubscribe", "unsubscribe", "punsubscribe",
    "ping", "client|setinfo", "client|setname",
)


def _admin():
    return get_redis(settings.REDIS_URL)


def is_delegate_user(name: str) -> bool:
    return bool(_UUID_RE.match(name))


def _rules(delegate_id: str) -> list:
    prefix = delegate_prefix(delegate_id)
    return [
        "reset", "on", f">{secrets.token_urlsafe(32)}",
        f"~{prefix}*", f"&{prefix}*",
        f"%W~{GLOBAL_EXECUTION_EVENTS_STREAM}",
        "-@all", *[f"+{c}" for c in DELEGATE_COMMANDS],
    ]


def save(r) -> None:
    """Persists ACLs to the aclfile so they survive a Redis restart."""
    try:
        r.execute_command("ACL", "SAVE")
    except Exception as exc:  # aclfile not configured, etc.
        logger.warning("ACL SAVE failed (ACLs are memory-only until fixed): %s", exc)


def provision_delegate(delegate_id) -> None:
    delegate_id = str(delegate_id)
    r = _admin()
    r.execute_command("ACL", "SETUSER", delegate_id, *_rules(delegate_id))
    save(r)


def revoke_delegate(delegate_id) -> int:
    """Deletes the delegate's ACL user, which also kills its open Redis
    connections. Returns the number of users deleted (0 or 1)."""
    r = _admin()
    deleted = r.execute_command("ACL", "DELUSER", str(delegate_id))
    save(r)
    return int(deleted)


def reconcile(active_delegate_ids) -> dict:
    """Makes Redis match the control-plane DB: every active delegate has a
    (freshly-ruled) ACL user, and every delegate-shaped user that is not
    active is deleted. Run at dispatcher startup, since ACLs live in Redis
    memory/aclfile, not in the DB."""
    active = {str(i) for i in active_delegate_ids}
    r = _admin()
    existing = {u for u in r.execute_command("ACL", "USERS") if is_delegate_user(u)}

    stale = existing - active
    for delegate_id in stale:
        r.execute_command("ACL", "DELUSER", delegate_id)
    for delegate_id in active:
        r.execute_command("ACL", "SETUSER", delegate_id, *_rules(delegate_id))
    save(r)
    return {"provisioned": sorted(active), "removed": sorted(stale)}
