"""Thin Celery client used only to enqueue execution tasks onto the broker
that Celery workers (bp-agent stand-ins) consume from. The control plane does
not need the task's implementation, just its registered name.

Each delegate's broker keys live under `delegate:<delegate_id>:` (kombu's
`global_keyprefix`), matching the key scope of that delegate's Redis ACL
user, so a task for one delegate can only ever land in that delegate's own
keyspace. Celery apps are therefore created per delegate (and cached), since
the prefix is a per-connection setting.
"""
import threading

from celery import Celery
from django.conf import settings

from delegate_protocol.redis_client import broker_ssl_options
from delegate_protocol.streams import delegate_prefix

_clients = {}
_lock = threading.Lock()


def _client_for(delegate_id: str) -> Celery:
    with _lock:
        client = _clients.get(delegate_id)
        if client is None:
            client = Celery(f"control_plane_client_{delegate_id}", broker=settings.REDIS_URL)
            conf = {"broker_transport_options": {"global_keyprefix": delegate_prefix(delegate_id)}}
            ssl_opts = broker_ssl_options()
            if ssl_opts:
                conf["broker_use_ssl"] = ssl_opts
            client.conf.update(**conf)
            _clients[delegate_id] = client
        return client


def send_execute_task(execution_id: str, delegate_id: str, queue: str = "default", file_name: str = "*"):
    return _client_for(str(delegate_id)).send_task(
        "worker_app.tasks.execute_task",
        args=[execution_id, file_name],
        queue=queue,
    )
