"""End-to-end happy-path smoke test against a running `docker compose up` stack.

Creates an execution against the small sample workspace on the worker_vm
delegate, polls until it reaches a terminal status, and checks the output
was received and validated by the control plane.

Usage: python scripts/e2e_smoke_test.py
"""
import os
import sys
import time

import requests

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://localhost:18000")
TENANT_ID = "tenant-demo"


def _get_delegate_id(name: str) -> str:
    # The registration flow doesn't expose a "list delegates" endpoint in
    # this POC; read it back out of the audit log instead.
    resp = requests.get(f"{CONTROL_PLANE_URL}/api/audit-events/", timeout=10)
    resp.raise_for_status()
    for event in resp.json()["events"]:
        if event["event_type"] == "DELEGATE_REGISTERED" and f"name={name}" in event["detail"]:
            return event["delegate_id"]
    raise RuntimeError(f"no DELEGATE_REGISTERED audit event found for name={name}")


def main():
    print("Waiting for vm-delegate-1 to register...")
    delegate_id = None
    for _ in range(60):
        try:
            delegate_id = _get_delegate_id("vm-delegate-1")
            break
        except RuntimeError:
            time.sleep(2)
    if not delegate_id:
        print("FAIL: vm-delegate-1 never registered")
        sys.exit(1)
    print(f"delegate_id={delegate_id}")

    resp = requests.post(f"{CONTROL_PLANE_URL}/api/executions/", json={
        "tenant_id": TENANT_ID, "delegate_id": delegate_id, "workspace_fixture": "sample_workspace",
    }, timeout=10)
    resp.raise_for_status()
    execution_id = resp.json()["execution_id"]
    print(f"execution_id={execution_id}")

    terminal = {"SUCCEEDED", "FAILED", "TRANSFER_FAILED"}
    status = None
    for _ in range(60):
        resp = requests.get(f"{CONTROL_PLANE_URL}/api/executions/{execution_id}/", timeout=10)
        resp.raise_for_status()
        body = resp.json()
        status = body["status"]
        print(f"status={status} logs={len(body['logs'])}")
        if status in terminal:
            break
        time.sleep(1)

    if status != "SUCCEEDED":
        print(f"FAIL: execution ended in status={status}")
        sys.exit(1)

    if not body["output_path"] or not body["output_checksum"]:
        print("FAIL: execution SUCCEEDED but no output was recorded")
        sys.exit(1)

    print("PASS: execution completed and output validated")
    print(f"  output_path={body['output_path']}")
    print(f"  output_checksum={body['output_checksum']}")
    for line in body["logs"]:
        print(f"  log: {line}")


if __name__ == "__main__":
    main()
