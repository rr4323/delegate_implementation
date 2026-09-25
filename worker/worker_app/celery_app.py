import json
import os

from celery import Celery

from delegate_protocol.redis_client import broker_ssl_options
from delegate_protocol.streams import delegate_prefix

CERT_DIR = os.environ.get("CERT_DIR", "/app/certs")

# entrypoint.py registers (writing identity.json) before importing this
# module, so the delegate's id is known here. It scopes every broker key this
# worker touches to `delegate:<delegate_id>:` (kombu's global_keyprefix) --
# exactly the key pattern this delegate's Redis ACL user is confined to.
with open(os.path.join(CERT_DIR, "identity.json")) as _f:
    _delegate_id = json.load(_f)["delegate_id"]

app = Celery("bp_worker", broker=os.environ.get("REDIS_URL", "rediss://redis:6379/0"))
app.conf.update(
    task_default_queue=os.environ.get("DELEGATE_QUEUE", "default"),
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    broker_connection_retry_on_startup=True,
    broker_use_ssl=broker_ssl_options(),
    # Celery's remote-control (pidbox), mingle, gossip and heartbeat use
    # pub/sub channels and broadcast keys outside a single delegate's
    # keyspace; a delegate's ACL user is deliberately not allowed those, and
    # this POC doesn't use them. worker_main() below is started with the
    # matching --without-* flags.
    worker_enable_remote_control=False,
    # kombu's redis transport only redelivers an unacked task (task_acks_late)
    # once this many seconds have passed since it was handed to a worker --
    # it defaults to 3600s, which would leave a task that died mid-transfer
    # stuck for an hour before recreate-from-start's retry logic ever gets a
    # second chance to run. Set it short so a killed worker's in-flight
    # execution becomes visible to another (or its own restarted) worker
    # quickly -- this is the "Celery retry semantics vs. recreate-from-start"
    # risk flagged in Delegate Implementation Plan.md's risk register.
    broker_transport_options={
        "visibility_timeout": 30,
        "global_keyprefix": delegate_prefix(_delegate_id),
    },
)

# Registers execute_task under the "worker_app.tasks.execute_task" name that
# the control plane's celery_client.send_task() targets.
import worker_app.tasks  # noqa: E402,F401
