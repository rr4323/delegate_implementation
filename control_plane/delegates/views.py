import datetime
import json
import os
import urllib.request
import uuid

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from . import ca, redis_acl
from .celery_client import send_execute_task
from .models import AuditEvent, Delegate, Execution, ExecutionLog, RegistrationToken


def _json_body(request):
    try:
        return json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return None


def _audit(event_type, **kwargs):
    AuditEvent.objects.create(event_type=event_type, **kwargs)


@csrf_exempt
@require_http_methods(["POST"])
def issue_registration_token(request):
    """Issues a short-lived, single-use registration token for a tenant.

    NOTE: intentionally unauthenticated in this POC so `docker compose up`
    can bootstrap a demo delegate end-to-end without a manual admin step.
    In production this is an admin/authenticated-user-only action.
    """
    body = _json_body(request)
    if body is None or not body.get("tenant_id"):
        return JsonResponse({"error": "tenant_id is required"}, status=400)

    tenant_id = body["tenant_id"]
    expires_at = timezone.now() + datetime.timedelta(seconds=settings.REGISTRATION_TOKEN_TTL_SECONDS)
    token = RegistrationToken.objects.create(tenant_id=tenant_id, expires_at=expires_at)
    _audit("REGISTRATION_TOKEN_ISSUED", tenant_id=tenant_id, detail=f"token={token.token}")
    return JsonResponse({"token": token.token, "expires_at": expires_at.isoformat()})


@csrf_exempt
@require_http_methods(["POST"])
def register_delegate(request):
    body = _json_body(request)
    if body is None:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    required = ("token", "tenant_id", "name", "csr_pem")
    missing = [f for f in required if not body.get(f)]
    if missing:
        return JsonResponse({"error": f"missing fields: {missing}"}, status=400)

    token_value = body["token"]
    tenant_id = body["tenant_id"]

    try:
        reg_token = RegistrationToken.objects.get(token=token_value)
    except RegistrationToken.DoesNotExist:
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail="unknown token")
        return JsonResponse({"error": "invalid registration token"}, status=403)

    if reg_token.used_at is not None:
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail="token already used")
        return JsonResponse({"error": "registration token already used"}, status=403)

    if reg_token.expires_at < timezone.now():
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail="token expired")
        return JsonResponse({"error": "registration token expired"}, status=403)

    if reg_token.tenant_id != tenant_id:
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail="tenant mismatch")
        return JsonResponse({"error": "tenant_id does not match token"}, status=403)

    # The delegate's id is minted before signing so it can be embedded as the
    # certificate's CN -- that's what lets the restart gateway verify a HELLO
    # message's claimed delegate_id against the TLS-verified peer cert
    # (agent_manager presents the delegate's cert) instead of trusting the
    # client's self-report (see agent_manager/agent_manager.py /
    # management/commands/restart_gateway.py).
    delegate_id = uuid.uuid4()

    try:
        cert_pem, serial, not_valid_after = ca.sign_csr(
            body["csr_pem"],
            common_name=str(delegate_id),
            validity_days=settings.DELEGATE_CERT_VALIDITY_DAYS,
        )
    except ValueError as exc:
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail=str(exc))
        return JsonResponse({"error": str(exc)}, status=400)

    # Redis access is provisioned before the delegate row exists and is not
    # left half-done: without an ACL user the delegate's cert would connect to
    # Redis as nobody, so refuse the registration instead of issuing an
    # identity that cannot work.
    try:
        redis_acl.provision_delegate(delegate_id)
    except Exception as exc:
        _audit("REGISTRATION_REJECTED", tenant_id=tenant_id, detail=f"redis ACL provisioning failed: {exc}")
        return JsonResponse({"error": "could not provision Redis access"}, status=503)

    delegate = Delegate.objects.create(
        id=delegate_id,
        tenant_id=tenant_id,
        name=body["name"],
        queue=body.get("queue", "default"),
        concurrency=int(body.get("concurrency", 1)),
        cert_serial=serial,
        cert_pem=cert_pem,
        cert_expires_at=not_valid_after,
    )

    reg_token.used_at = timezone.now()
    reg_token.save(update_fields=["used_at"])

    _audit("DELEGATE_REGISTERED", tenant_id=tenant_id, delegate_id=str(delegate.id),
           detail=f"name={delegate.name} serial={serial}")
    _audit("REDIS_ACL_PROVISIONED", tenant_id=tenant_id, delegate_id=str(delegate.id),
           detail=f"scope=delegate:{delegate.id}:*")

    return JsonResponse({
        "delegate_id": str(delegate.id),
        "cert_pem": cert_pem,
        "ca_cert_pem": ca.ca_cert_pem(),
        "cert_expires_at": not_valid_after.isoformat(),
    })


@csrf_exempt
@require_http_methods(["POST"])
def revoke_delegate(request, delegate_id):
    try:
        delegate = Delegate.objects.get(id=delegate_id)
    except Delegate.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    # Revocation fans out. The DB status stops new task assignment and the
    # dispatcher's ownership checks; the Redis ACL user is what actually cuts
    # off the delegate's cert on the data path (a cert can't be revoked
    # mid-lifetime); the gateway websocket is closed so the delegate can't
    # keep a restart channel open. Each step is independent: a failure in one
    # is reported but doesn't skip the others.
    delegate.status = Delegate.STATUS_REVOKED
    delegate.save(update_fields=["status"])
    _audit("DELEGATE_REVOKED", tenant_id=delegate.tenant_id, delegate_id=str(delegate.id))

    result = {"status": "revoked", "redis_acl_removed": False, "gateway_disconnected": False}
    try:
        result["redis_acl_removed"] = redis_acl.revoke_delegate(delegate.id) > 0
        _audit("REDIS_ACL_REVOKED", tenant_id=delegate.tenant_id, delegate_id=str(delegate.id),
               detail=f"user_deleted={result['redis_acl_removed']} (open connections terminated)")
    except Exception as exc:
        _audit("REDIS_ACL_REVOKE_FAILED", tenant_id=delegate.tenant_id, delegate_id=str(delegate.id),
               detail=str(exc))

    try:
        req = urllib.request.Request(
            f"{settings.RESTART_GATEWAY_CONTROL_URL}/disconnect/{delegate.id}", method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result["gateway_disconnected"] = json.loads(resp.read()).get("disconnected", False)
    except Exception as exc:
        _audit("GATEWAY_DISCONNECT_FAILED", tenant_id=delegate.tenant_id, delegate_id=str(delegate.id),
               detail=str(exc))
    return JsonResponse(result)


@csrf_exempt
@require_http_methods(["POST"])
def create_execution(request):
    body = _json_body(request)
    if body is None:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    required = ("tenant_id", "delegate_id", "workspace_fixture")
    missing = [f for f in required if not body.get(f)]
    if missing:
        return JsonResponse({"error": f"missing fields: {missing}"}, status=400)

    try:
        delegate = Delegate.objects.get(id=body["delegate_id"])
    except Delegate.DoesNotExist:
        return JsonResponse({"error": "unknown delegate_id"}, status=404)

    if delegate.tenant_id != body["tenant_id"]:
        return JsonResponse({"error": "delegate does not belong to tenant"}, status=403)
    if delegate.status != Delegate.STATUS_ACTIVE:
        return JsonResponse({"error": "delegate is not active"}, status=403)

    fixture_path = os.path.join(settings.WORKSPACE_FIXTURES_DIR, body["workspace_fixture"])
    if not os.path.isdir(fixture_path):
        return JsonResponse({"error": f"workspace fixture not found: {fixture_path}"}, status=400)

    file_name = body.get("file_name", "*")

    execution = Execution.objects.create(
        execution_id=uuid.uuid4(),
        tenant_id=body["tenant_id"],
        delegate=delegate,
        workspace_fixture=body["workspace_fixture"],
        status=Execution.STATUS_QUEUED,
    )

    send_execute_task(str(execution.execution_id), str(delegate.id), queue=delegate.queue, file_name=file_name)

    _audit("EXECUTION_CREATED", tenant_id=execution.tenant_id, delegate_id=str(delegate.id),
           execution_id=str(execution.execution_id), detail=f"file_name={file_name}")

    return JsonResponse({"execution_id": str(execution.execution_id), "status": execution.status})


@require_http_methods(["GET"])
def execution_status(request, execution_id):
    try:
        execution = Execution.objects.get(execution_id=execution_id)
    except Execution.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)

    logs = list(execution.logs.values_list("line", flat=True))
    return JsonResponse({
        "execution_id": str(execution.execution_id),
        "tenant_id": execution.tenant_id,
        "delegate_id": str(execution.delegate_id) if execution.delegate_id else None,
        "status": execution.status,
        "transfer_id": execution.transfer_id,
        "transfer_attempts": execution.transfer_attempts,
        "output_path": execution.output_path,
        "output_checksum": execution.output_checksum,
        "logs": logs,
    })


@require_http_methods(["GET"])
def list_audit_events(request):
    events = AuditEvent.objects.all()[:200]
    return JsonResponse({"events": [
        {
            "event_type": e.event_type,
            "tenant_id": e.tenant_id,
            "delegate_id": e.delegate_id,
            "execution_id": e.execution_id,
            "detail": e.detail,
            "created_at": e.created_at.isoformat(),
        } for e in events
    ]})
