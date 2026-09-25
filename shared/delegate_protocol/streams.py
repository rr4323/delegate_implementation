"""Stream naming shared by the worker (bp-agent stand-in) and the control
plane, so both sides always agree on where a given execution's traffic
lives. Also defines the one global stream new executions are announced on.

Every per-delegate key -- the execution streams below *and* the Celery
broker's keys (via kombu's `global_keyprefix`) -- lives under
`delegate:<delegate_id>:`. That is what lets each delegate's Redis ACL user
be confined by a single static key pattern (see
control_plane/delegates/redis_acl.py) instead of per-execution grants.
"""

GLOBAL_EXECUTION_EVENTS_STREAM = "global:execution_events"


def delegate_prefix(delegate_id: str) -> str:
    return f"delegate:{delegate_id}:"


def stream_keys(execution_id: str, delegate_id: str) -> dict:
    base = f"{delegate_prefix(delegate_id)}execution:{execution_id}"
    return {
        "events": f"{base}:events",
        "log": f"{base}:log",
        "status": f"{base}:status",
        "output": f"{base}:output",
    }
