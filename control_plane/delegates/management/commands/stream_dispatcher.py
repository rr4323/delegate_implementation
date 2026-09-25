"""The control-plane half of the delegate protocol.

Plays the role the design doc assigns to `public_api` / `scheduled_api`
around task execution: answers DATA_REQUEST with a chunked workspace ZIP,
persists logs/status as they stream in, and validates+stores the output
transfer. One background thread watches each active execution's four Redis
Streams (`events`, `log`, `status`, `output`) concurrently -- this is the
mechanism Goal 4 in Delegate POC.md is validating.

New executions are discovered by consuming the global
`GLOBAL_EXECUTION_EVENTS_STREAM`, not by polling the database: the worker
announces an execution (via the `task_prerun` signal in
worker/worker_app/tasks.py) right before it starts working on it, and this
command just reacts. The announcement is only a *hint* that an execution
exists: delegates can write to the global stream (write-only), so its
contents are untrusted. The stream names this process actually reads are
derived from the execution's assigned delegate in the DB via the shared
`stream_keys()`, never from the announcement -- a delegate cannot point the
dispatcher at another delegate's streams (a mismatch is audited).

On startup the dispatcher also reconciles Redis ACL users with the delegate
table (delegates/redis_acl.py), since ACLs live in Redis, not in the DB.

Simplifications vs. production (see ../../../README.md for the full list):
plain XREAD with an in-memory last-id cursor, not Redis consumer groups, for
both the global stream and each execution's four streams. A dispatcher
restart starts reading the global stream from its beginning, which is fine
at POC scale but would need a consumer-group offset (or a periodic DB
reconciliation sweep as a backstop) to be reliable with multiple dispatcher
replicas or a dispatcher that's down when an announcement fires.
"""
import base64
import os
import threading
import time
from datetime import datetime

import redis

from django.conf import settings
from django.core.management.base import BaseCommand

from delegate_protocol.chunked_transfer import (
    ChunkSender, sha256_bytes, zip_directory_to_bytes, zip_single_file_to_bytes,
)
from delegate_protocol.redis_client import get_redis
from delegate_protocol.streams import GLOBAL_EXECUTION_EVENTS_STREAM, stream_keys
from delegates import ca, redis_acl
from delegates.models import AuditEvent, Delegate, Execution, ExecutionLog

def _log(execution_id, message):
    """Timestamped, flushed line so each protocol step is visible live in the
    dispatcher's terminal. `execution_id` is None for global (non-execution)
    lines; watcher threads interleave, so it's shown on every line.
    """
    prefix = f"[{str(execution_id)[:8]}] " if execution_id else ""
    print(f"{datetime.now():%H:%M:%S} [dispatcher] {prefix}{message}", flush=True)


STATUS_MAPPING = {
    "TRANSFERRING_INPUT": Execution.STATUS_TRANSFERRING,
    "EXECUTING": Execution.STATUS_RUNNING,
    "TRANSFER_FAILED": Execution.STATUS_TRANSFER_FAILED,
    "TASK_FAILED": Execution.STATUS_FAILED,
    # TASK_SUCCEEDED is intentionally not mapped: the control plane only
    # marks an execution SUCCEEDED after independently validating the
    # output transfer below, not by trusting the worker's self-report.
}


def _announced_keys(fields):
    return {
        "events": fields.get("events_stream"),
        "log": fields.get("log_stream"),
        "status": fields.get("status_stream"),
        "output": fields.get("output_stream"),
    }


def _handle_data_request(r, execution_id, events_key, fields):
    tenant_id = fields.get("tenant_id", "")
    delegate_id = fields.get("delegate_id", "")
    _log(execution_id, f"DATA_REQUEST received on {events_key} "
                       f"(delegate={delegate_id[:8]} tenant={tenant_id} requested_file={fields.get('requested_file', '*')!r})")

    try:
        execution = Execution.objects.get(execution_id=execution_id)
    except Execution.DoesNotExist:
        _log(execution_id, "DATA_REQUEST ignored: no such execution in DB")
        return

    delegate = Delegate.objects.filter(id=delegate_id).first()
    authorized = (
        delegate is not None
        and delegate.status == Delegate.STATUS_ACTIVE
        and delegate.tenant_id == tenant_id
        and execution.tenant_id == tenant_id
        and str(execution.delegate_id) == str(delegate_id)
    )
    if not authorized:
        _log(execution_id, "DATA_REQUEST REJECTED: tenant/delegate ownership check failed")
        AuditEvent.objects.create(
            event_type="DATA_REQUEST_REJECTED", tenant_id=tenant_id, delegate_id=delegate_id,
            execution_id=str(execution_id), detail="tenant/delegate ownership check failed",
        )
        return

    fixture_dir = os.path.join(settings.WORKSPACE_FIXTURES_DIR, execution.workspace_fixture)
    requested_file = fields.get("requested_file", "*")
    if requested_file in ("*", "", None):
        zip_bytes = zip_directory_to_bytes(fixture_dir)
    else:
        zip_bytes = zip_single_file_to_bytes(fixture_dir, requested_file)
        if zip_bytes is None:
            _log(execution_id, f"DATA_REQUEST: requested_file={requested_file!r} not found; sending nothing")
            AuditEvent.objects.create(
                event_type="DATA_REQUEST_FILE_NOT_FOUND", tenant_id=tenant_id, delegate_id=delegate_id,
                execution_id=str(execution_id),
                detail=f"requested_file={requested_file!r} not found in {execution.workspace_fixture}",
            )
            return

    _log(execution_id, f"ownership check passed; sending workspace ZIP ({len(zip_bytes)} bytes) on {events_key}")
    sender = ChunkSender(r)
    transfer_id, _checksum, total_size = sender.send_bytes(
        events_key, zip_bytes, {"execution_id": str(execution_id), "tenant_id": tenant_id},
    )
    _log(execution_id, f"workspace transfer {transfer_id} sent (DATA_START..DATA_END, {total_size} bytes)")

    execution.status = Execution.STATUS_TRANSFERRING
    execution.transfer_id = transfer_id
    execution.transfer_attempts += 1
    execution.save(update_fields=["status", "transfer_id", "transfer_attempts", "updated_at"])

    AuditEvent.objects.create(
        event_type="WORKSPACE_TRANSFER_SENT", tenant_id=tenant_id, delegate_id=delegate_id,
        execution_id=str(execution_id), detail=f"transfer_id={transfer_id} size={total_size}",
    )


def _handle_log(execution_id, fields, seq):
    _log(execution_id, f"LOG #{seq}: {fields.get('message', '')}")
    ExecutionLog.objects.create(
        execution_id=execution_id, seq=seq, line=fields.get("message", ""),
    )


def _handle_status(execution_id, fields):
    status = fields.get("status", "")
    _log(execution_id, f"STATUS from worker: {status}")
    AuditEvent.objects.create(
        event_type="WORKER_STATUS", execution_id=str(execution_id),
        tenant_id=fields.get("tenant_id", ""), delegate_id=fields.get("delegate_id", ""), detail=status,
    )
    new_status = STATUS_MAPPING.get(status)
    if new_status:
        Execution.objects.filter(execution_id=execution_id).update(status=new_status)


def _handle_output_message(execution_id, fields, state, media_root):
    mtype = fields.get("type")

    if mtype == "DATA_START":
        _log(execution_id, f"output DATA_START transfer_id={fields.get('transfer_id')} total_size={fields.get('total_size')}")
        return {
            "transfer_id": fields["transfer_id"],
            "total_size": int(fields["total_size"]),
            "checksum": fields["checksum"],
            "buf": bytearray(),
            "seen_seq": set(),
        }

    if state is None:
        return None

    if mtype == "DATA_CHUNK" and fields.get("transfer_id") == state["transfer_id"]:
        seq = int(fields["sequence_no"])
        if seq not in state["seen_seq"]:
            state["seen_seq"].add(seq)
            state["buf"].extend(base64.b64decode(fields["chunk_b64"]))
        return state

    if mtype == "DATA_END" and fields.get("transfer_id") == state["transfer_id"]:
        data = bytes(state["buf"])
        valid = len(data) == state["total_size"] and sha256_bytes(data) == state["checksum"]
        _log(execution_id, f"output DATA_END: received {len(data)} bytes in {len(state['seen_seq'])} chunks, valid={valid}")
        if valid:
            out_dir = os.path.join(media_root, "outputs")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"{execution_id}.zip")
            with open(out_path, "wb") as f:
                f.write(data)
            Execution.objects.filter(execution_id=execution_id).update(
                status=Execution.STATUS_SUCCEEDED, output_path=out_path, output_checksum=state["checksum"],
            )
            AuditEvent.objects.create(
                event_type="OUTPUT_RECEIVED", execution_id=str(execution_id),
                detail=f"path={out_path} size={len(data)}",
            )
        else:
            Execution.objects.filter(execution_id=execution_id).update(status=Execution.STATUS_FAILED)
            AuditEvent.objects.create(
                event_type="OUTPUT_VALIDATION_FAILED", execution_id=str(execution_id),
                detail="size or checksum mismatch on output transfer",
            )
        return None

    return state


def _cleanup_execution_streams(r, execution_id, keys):
    """Deletes an execution's four per-execution streams once its watcher is
    done with them. Only ever called from watch_execution, and only once it
    has already observed a terminal status (or given up) -- by that point
    every message that will ever matter has already been read and processed,
    so there's no race with anything still trying to consume from them.
    Matches the design doc: "task-specific streams are cleaned according to
    the retention policy."
    """
    r.delete(*keys.values())
    _log(execution_id, f"deleted streams {list(keys.values())}")
    AuditEvent.objects.create(
        event_type="STREAMS_CLEANED", execution_id=str(execution_id),
        detail=f"deleted {list(keys.values())}",
    )


def watch_execution(execution_id, keys, redis_url, media_root, max_lifetime_seconds):
    """Parallel per-execution consumer: one of these runs per active
    execution, each independently XREAD-ing its own four streams. Spawned by
    Command.handle() in reaction to an EXECUTION_STARTED announcement on the
    global stream, not by polling.
    """
    r = get_redis(redis_url)
    last_ids = {key: "0" for key in keys.values()}
    _log(execution_id, "watcher thread started; XREAD-ing " + ", ".join(keys.values()))
    log_seq = 0
    output_state = None
    deadline = time.time() + max_lifetime_seconds

    while time.time() < deadline:
        try:
            execution = Execution.objects.get(execution_id=execution_id)
        except Execution.DoesNotExist:
            return
        if execution.status in Execution.TERMINAL_STATUSES:
            _log(execution_id, f"execution reached terminal status {execution.status}; cleaning up")
            _cleanup_execution_streams(r, execution_id, keys)
            return

        try:
            resp = r.xread(last_ids, count=50, block=2000)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as exc:
            # e.g. Redis restarted. The client reconnects on the next call;
            # just don't let this execution's watcher die and strand it.
            _log(execution_id, f"Redis connection lost ({exc.__class__.__name__}); retrying in 2s")
            time.sleep(2)
            continue
        if not resp:
            continue

        for stream_key, messages in resp:
            for msg_id, fields in messages:
                last_ids[stream_key] = msg_id
                mtype = fields.get("type")
                if mtype not in ("LOG", "DATA_CHUNK"):  # chatty types are logged by their handlers / summarized
                    _log(execution_id, f"<- {stream_key.rsplit(':', 1)[-1]} stream: {mtype}")

                if stream_key == keys["events"] and mtype == "DATA_REQUEST":
                    _handle_data_request(r, execution_id, keys["events"], fields)
                elif stream_key == keys["log"] and mtype == "LOG":
                    log_seq += 1
                    _handle_log(execution_id, fields, log_seq)
                elif stream_key == keys["status"] and mtype == "STATUS":
                    _handle_status(execution_id, fields)
                elif stream_key == keys["output"]:
                    output_state = _handle_output_message(execution_id, fields, output_state, media_root)

    _log(execution_id, f"watcher gave up: no terminal status within {max_lifetime_seconds}s")
    AuditEvent.objects.create(
        event_type="DISPATCHER_WATCH_TIMED_OUT", execution_id=str(execution_id),
        detail=f"no terminal status reached within {max_lifetime_seconds}s",
    )
    _cleanup_execution_streams(r, execution_id, keys)


def _reconcile_acls():
    active_ids = list(Delegate.objects.filter(status=Delegate.STATUS_ACTIVE).values_list("id", flat=True))
    result = redis_acl.reconcile(active_ids)
    _log(None, f"reconciled Redis ACLs with DB: {len(result['provisioned'])} active delegate user(s), "
               f"removed {len(result['removed'])} stale user(s)")


class Command(BaseCommand):
    help = "Consumes the global execution-announcement stream and drives the control-plane side of the protocol."

    @staticmethod
    def _reconcile_acls_when_back(retry_forever=False):
        """Runs the ACL reconcile; after a Redis outage it is repeated on
        reconnect in case Redis came back without its ACL users (e.g. lost
        aclfile). At startup it retries until Redis is reachable."""
        while True:
            try:
                _reconcile_acls()
                return
            except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as exc:
                if not retry_forever:
                    return  # still down; the main loop will call this again
                _log(None, f"Redis not reachable yet ({exc.__class__.__name__}); retrying in 2s")
                time.sleep(2)

    def handle(self, *args, **options):
        ca.ensure_root_ca()
        ca.ensure_control_plane_server_cert()

        self._reconcile_acls_when_back(retry_forever=True)

        r = get_redis(settings.REDIS_URL)
        watched = {}
        last_id = "0"
        self.stdout.write(self.style.SUCCESS(
            f"stream_dispatcher started, consuming {GLOBAL_EXECUTION_EVENTS_STREAM}"
        ))

        while True:
            try:
                resp = r.xread({GLOBAL_EXECUTION_EVENTS_STREAM: last_id}, count=50, block=2000)
            except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError) as exc:
                _log(None, f"Redis connection lost ({exc.__class__.__name__}); retrying in 2s")
                time.sleep(2)
                self._reconcile_acls_when_back()
                continue
            for _stream, messages in resp:
                for msg_id, fields in messages:
                    last_id = msg_id
                    if fields.get("type") != "EXECUTION_STARTED":
                        continue
                    execution_id = fields.get("execution_id")
                    if not execution_id:
                        continue
                    _log(execution_id, f"EXECUTION_STARTED announced on {GLOBAL_EXECUTION_EVENTS_STREAM} (msg {msg_id})")

                    existing = watched.get(execution_id)
                    if existing is not None and existing.is_alive():
                        _log(execution_id, "already being watched; ignoring re-announcement")
                        continue  # already being watched (e.g. a re-announced/retried task)

                    execution = Execution.objects.filter(execution_id=execution_id).first()
                    if execution is None or execution.delegate_id is None:
                        _log(execution_id, "announcement ignored: no such execution in DB")
                        continue
                    keys = stream_keys(execution_id, execution.delegate_id)
                    if _announced_keys(fields) != keys:
                        _log(execution_id, "announced stream names do not match the assigned delegate's "
                                           "streams; using the DB-derived names")
                        AuditEvent.objects.create(
                            event_type="ANNOUNCEMENT_STREAM_MISMATCH", execution_id=str(execution_id),
                            delegate_id=str(execution.delegate_id), tenant_id=execution.tenant_id,
                            detail=f"announced={_announced_keys(fields)}",
                        )
                    _log(execution_id, "attaching to worker-created streams (Redis creates a stream on the worker's first XADD): "
                                       + ", ".join(f"{k}={v}" for k, v in keys.items()))
                    t = threading.Thread(
                        target=watch_execution,
                        args=(execution_id, keys, settings.REDIS_URL, settings.MEDIA_ROOT, 600),
                        daemon=True,
                    )
                    t.start()
                    watched[execution_id] = t

            watched = {k: v for k, v in watched.items() if v.is_alive()}
