"""Validates Goal 3 from Delegate POC.md: recreate-from-start recovery.

Runs an execution against a large workspace fixture, kills the worker_vm
container partway through the chunked transfer (`docker kill`, simulating a
worker process/network failure), lets Docker's restart policy bring it back,
and confirms the execution still reaches SUCCEEDED via a full retransmit
(transfer_attempts > 1) rather than hanging or corrupting the workspace.

Usage: python scripts/kill_mid_transfer_test.py
Requires: `docker compose up -d` already running, and a large fixture at
fixtures/large_workspace (generated automatically if missing).
"""
import os
import subprocess
import sys
import time

import requests

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:18000")
TENANT_ID = "tenant-demo"
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
LARGE_WORKSPACE = os.path.join(FIXTURES_DIR, "large_workspace")


def _ensure_large_fixture():
    if os.path.isdir(LARGE_WORKSPACE) and os.listdir(LARGE_WORKSPACE):
        return
    print("Generating large workspace fixture (~200MB)...")
    subprocess.run(
        [sys.executable, os.path.join(FIXTURES_DIR, "make_large_workspace.py"), "200", LARGE_WORKSPACE],
        check=True,
    )


def _get_delegate_id(name: str) -> str:
    resp = requests.get(f"{CONTROL_PLANE_URL}/api/audit-events/", timeout=10)
    for event in resp.json()["events"]:
        if event["event_type"] == "DELEGATE_REGISTERED" and f"name={name}" in event["detail"]:
            return event["delegate_id"]
    raise RuntimeError(f"no DELEGATE_REGISTERED audit event found for name={name}")


def _find_worker_container() -> str:
    out = subprocess.run(
        ["docker", "ps", "--filter", "label=com.docker.compose.service=worker_vm",
         "--format", "{{.Names}}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().splitlines()
    if not out:
        raise RuntimeError("worker_vm container not found; is docker compose up?")
    return out[0]


def main():
    _ensure_large_fixture()

    delegate_id = None
    for _ in range(30):
        try:
            delegate_id = _get_delegate_id("vm-delegate-1")
            break
        except RuntimeError:
            time.sleep(2)
    if not delegate_id:
        print("FAIL: vm-delegate-1 never registered")
        sys.exit(1)

    resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": TENANT_ID, "delegate_id": delegate_id, "workspace_fixture": "large_workspace",
    }, timeout=10)
    resp.raise_for_status()
    execution_id = resp.json()["execution_id"]
    print(f"execution_id={execution_id}")

    print("Waiting for transfer to begin...")
    for _ in range(30):
        body = requests.get(f"{CONTROL_PLANE_URL}/api/executions/{execution_id}/", timeout=10).json()
        if body["status"] == "TRANSFERRING":
            break
        time.sleep(0.5)
    else:
        print("FAIL: transfer never started")
        sys.exit(1)

    time.sleep(0.5)  # let a handful of chunks land before killing

    container = _find_worker_container()
    print(f"Killing {container} mid-transfer...")
    subprocess.run(["docker", "kill", container], check=True)

    # Docker's restart policy deliberately does NOT auto-restart a container
    # after an explicit `docker kill`/`docker stop` -- those are treated as
    # intentional operator actions, not crashes, so `restart: unless-stopped`
    # never fires here (verified against this host's dockerd; see
    # ../README.md). In production this recovery step is what a process
    # supervisor, Kubernetes' pod restart, or `agent_manager` would do on
    # detecting the worker is gone -- so the test performs it explicitly.
    time.sleep(2)
    print(f"Bringing {container} back up (simulating supervisor/K8s restart)...")
    subprocess.run(["docker", "start", container], check=True)

    terminal = {"SUCCEEDED", "FAILED", "TRANSFER_FAILED"}
    status = None
    body = {}
    for _ in range(120):
        try:
            resp = requests.get(f"{CONTROL_PLANE_URL}/api/executions/{execution_id}/", timeout=10)
            body = resp.json()
            status = body["status"]
        except requests.RequestException:
            status = None
        print(f"status={status} transfer_attempts={body.get('transfer_attempts')}")
        if status in terminal:
            break
        time.sleep(2)

    if status != "SUCCEEDED":
        print(f"FAIL: execution ended in status={status}, expected SUCCEEDED after recovery")
        sys.exit(1)

    if body.get("transfer_attempts", 0) < 2:
        print("FAIL: execution succeeded but transfer_attempts suggests no retry happened "
              "(the kill may have landed after the transfer already finished -- try again)")
        sys.exit(1)

    print(f"PASS: execution recovered via recreate-from-start after {body['transfer_attempts']} attempt(s)")


if __name__ == "__main__":
    main()
