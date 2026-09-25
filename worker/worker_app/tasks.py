"""The Celery task that plays the role of `bp-agent` receiving and running a
task, per the "Delegate-Based Task Execution" lifecycle in Delegate Design.md.

That lifecycle splits cleanly into two phases, and the code here mirrors the
split rather than doing everything inline in one function:

  1. (steps 3-6, in `_prepare_execution` below, a `task_prerun` signal) --
     announce the execution, request the workspace data, and reconstruct it
     via the chunked transfer protocol. This runs once this worker has
     actually claimed the task, before the task body executes at all.
  2. (steps 7+, in `execute_task`'s body) -- run task_executor against the
     already-prepared workspace, stream logs/status, send the output back.

If phase 1 fails (transfer never succeeds after retries), the task body
never gets a workspace to look at and returns immediately without doing any
execution work -- `TRANSFER_FAILED` was already published by the signal
handler.
"""
import json
import os
import shutil
import tempfile

from celery.signals import task_prerun

from delegate_protocol.chunked_transfer import (
    ChunkReceiver, ChunkSender, TransferFailed, extract_zip_bytes, zip_directory_to_bytes,
)
from delegate_protocol.redis_client import get_redis
from delegate_protocol.streams import GLOBAL_EXECUTION_EVENTS_STREAM, stream_keys

from worker_app.celery_app import app
from worker_app.executor import run_stub_task

CERT_DIR = os.environ.get("CERT_DIR", "/app/certs")
# Debug-only: the real workspace_dir is a tempfile.mkdtemp() that execute_task
# rmtree's in its `finally` right after the task runs, so there's normally no
# window to go look at what a DATA_REQUEST actually pulled down. This mirrors
# that same content into a folder that is never cleaned up, purely so it can
# be inspected after the fact -- not something a real deployment would want
# (it grows without bound, one subfolder per execution).
TEMP_WORKSPACE_DIR = os.environ.get("TEMP_WORKSPACE_DIR", "temp_workspace")
REDIS_URL = os.environ.get("REDIS_URL", "rediss://redis:6379/0")
TRANSFER_WAIT_TIMEOUT = float(os.environ.get("TRANSFER_WAIT_TIMEOUT_SECONDS", "15"))
TRANSFER_MAX_RETRIES = int(os.environ.get("TRANSFER_MAX_RETRIES", "5"))

# task_id -> workspace_dir, populated by _prepare_execution and consumed by
# execute_task's body. Process-local: Celery's prefork pool runs at most one
# task at a time per child process, so this never needs cross-process
# locking, only a dict keyed by task_id to keep concurrent-in-this-process
# (threaded/eventlet pools) or back-to-back task invocations from colliding.
_prepared_workspaces = {}


def _identity() -> dict:
    with open(os.path.join(CERT_DIR, "identity.json")) as f:
        return json.load(f)


def _publish_log(r, log_key, base_fields, message):
    r.xadd(log_key, {**base_fields, "type": "LOG", "message": message})


def _publish_status(r, status_key, base_fields, status):
    r.xadd(status_key, {**base_fields, "type": "STATUS", "status": status})


def _receive_workspace(r, events_key, base_fields, workspace_dir, log_fn, requested_file: str) -> bool:
    """Implements the Chunked ZIP Transfer Protocol's recreate-from-start
    recovery: on TransferFailed, discard everything and re-issue DATA_REQUEST
    to get a brand new transfer_id, rather than resuming from an offset.

    `requested_file` is "*" for the whole workspace, or a specific path
    within it -- the design doc's DATA_REQUEST carries "requested paths/files",
    not just an unconditional "send everything".
    """
    receiver = ChunkReceiver(r, events_key, wait_timeout=TRANSFER_WAIT_TIMEOUT)
    last_id = "0"
    for attempt in range(1, TRANSFER_MAX_RETRIES + 1):
        r.xadd(events_key, {**base_fields, "type": "DATA_REQUEST", "requested_file": requested_file})
        log_fn(f"DATA_REQUEST sent (attempt {attempt}/{TRANSFER_MAX_RETRIES})")
        try:
            data, last_id, transfer_id = receiver.receive_once(last_id)
        except TransferFailed as exc:
            last_id = exc.last_id or last_id
            log_fn(f"transfer attempt {attempt} failed: {exc}; retrying from scratch")
            continue

        extract_zip_bytes(data, workspace_dir)
        log_fn(f"workspace transfer {transfer_id} validated and extracted ({len(data)} bytes)")
        return True

    return False


def _mirror_to_temp_workspace(execution_id, workspace_dir, log_fn):
    """Copies the just-extracted workspace into TEMP_WORKSPACE_DIR/<execution_id>/
    so there's something left to look at after execute_task's `finally` rmtree's
    the real workspace_dir a few seconds from now. See TEMP_WORKSPACE_DIR's
    definition above for why this exists and why it's debug-only."""
    dest = os.path.join(TEMP_WORKSPACE_DIR, str(execution_id))
    try:
        shutil.rmtree(dest, ignore_errors=True)  # a retried/re-announced execution_id would otherwise merge into it
        shutil.copytree(workspace_dir, dest)
        log_fn(f"mirrored workspace to {os.path.abspath(dest)} for inspection (not cleaned up automatically)")
    except OSError as exc:
        log_fn(f"could not mirror workspace to {dest}: {exc}")


def _send_output(r, output_key, base_fields, output_dir, log_fn):
    data = zip_directory_to_bytes(output_dir)
    sender = ChunkSender(r)
    transfer_id, _checksum, size = sender.send_bytes(output_key, data, base_fields)
    log_fn(f"output transfer {transfer_id} sent ({size} bytes)")


@app.task(name="worker_app.tasks.execute_task", bind=True)
def execute_task(self, execution_id: str, file_name: str = "*"):
    workspace_dir = _prepared_workspaces.pop(self.request.id, None)
    if workspace_dir is None:
        # _prepare_execution already published TRANSFER_FAILED (or this
        # invocation had no execution_id to begin with) -- nothing to run.
        return

    identity = _identity()
    r = get_redis(REDIS_URL)
    keys = stream_keys(execution_id, identity["delegate_id"])
    base_fields = {
        "execution_id": execution_id,
        "tenant_id": identity["tenant_id"],
        "delegate_id": identity["delegate_id"],
    }

    def log_fn(message):
        _publish_log(r, keys["log"], base_fields, message)

    output_dir = tempfile.mkdtemp(prefix="output-")
    try:
        _publish_status(r, keys["status"], base_fields, "EXECUTING")
        run_stub_task(workspace_dir, output_dir, log_fn)

        _send_output(r, keys["output"], base_fields, output_dir, log_fn)
        _publish_status(r, keys["status"], base_fields, "TASK_SUCCEEDED")
    except Exception as exc:
        log_fn(f"task failed with exception: {exc}")
        _publish_status(r, keys["status"], base_fields, "TASK_FAILED")
        raise
    finally:
        shutil.rmtree(workspace_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


# sender must be the actual task object (not its name as a string) -- Celery
# sends this signal with sender=<task instance>, and connect()'s sender
# filter does an identity/equality check against that, so a string here
# would silently never match and this handler would never fire.
@task_prerun.connect(sender=execute_task)
def _prepare_execution(sender, task_id, task, args, kwargs, **_extra):
    """Environment setup, run before `execute_task`'s body: announce the
    execution on the global stream (see stream_dispatcher.py -- this is what
    lets the control plane discover it without polling the database), then
    request and reconstruct the workspace. Leaves `workspace_dir` in
    `_prepared_workspaces[task_id]` only on success; the task body checks for
    that and does nothing if it's absent.
    """
    execution_id = args[0] if args else kwargs.get("execution_id")
    if not execution_id:
        return
    requested_file = args[1] if len(args) > 1 else kwargs.get("file_name", "*")

    identity = _identity()
    r = get_redis(REDIS_URL)
    keys = stream_keys(execution_id, identity["delegate_id"])
    base_fields = {
        "execution_id": execution_id,
        "tenant_id": identity["tenant_id"],
        "delegate_id": identity["delegate_id"],
    }

    def log_fn(message):
        _publish_log(r, keys["log"], base_fields, message)

    # Announce before touching any of the per-execution streams below, so
    # the dispatcher's watcher is started as early as possible. Harmless if
    # it's still a moment behind: the watcher reads each stream from
    # position "0", so nothing published before it attaches is ever missed.
    r.xadd(GLOBAL_EXECUTION_EVENTS_STREAM, {
        "type": "EXECUTION_STARTED",
        "execution_id": execution_id,
        "events_stream": keys["events"],
        "log_stream": keys["log"],
        "status_stream": keys["status"],
        "output_stream": keys["output"],
    })

    _publish_status(r, keys["status"], base_fields, "TRANSFERRING_INPUT")
    workspace_dir = tempfile.mkdtemp(prefix="workspace-")
    received = _receive_workspace(r, keys["events"], base_fields, workspace_dir, log_fn, requested_file)
    if not received:
        _publish_status(r, keys["status"], base_fields, "TRANSFER_FAILED")
        log_fn("workspace transfer failed after max retries; giving up")
        shutil.rmtree(workspace_dir, ignore_errors=True)
        return

    _prepared_workspaces[task_id] = workspace_dir
    _mirror_to_temp_workspace(execution_id, workspace_dir, log_fn)
