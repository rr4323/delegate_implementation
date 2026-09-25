import uuid

from django.db import models


def _generate_token() -> str:
    return uuid.uuid4().hex


class RegistrationToken(models.Model):
    token = models.CharField(max_length=64, primary_key=True, default=_generate_token)
    tenant_id = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.token} ({self.tenant_id})"


class Delegate(models.Model):
    STATUS_ACTIVE = "ACTIVE"
    STATUS_REVOKED = "REVOKED"
    STATUS_CHOICES = [(STATUS_ACTIVE, "Active"), (STATUS_REVOKED, "Revoked")]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=128, db_index=True)
    name = models.CharField(max_length=128)
    queue = models.CharField(max_length=128, default="default")
    concurrency = models.IntegerField(default=1)
    cert_serial = models.CharField(max_length=64)
    cert_pem = models.TextField()
    cert_expires_at = models.DateTimeField()
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} [{self.tenant_id}] ({self.status})"


class Execution(models.Model):
    STATUS_QUEUED = "QUEUED"
    STATUS_TRANSFERRING = "TRANSFERRING"
    STATUS_TRANSFER_FAILED = "TRANSFER_FAILED"
    STATUS_RUNNING = "RUNNING"
    STATUS_SUCCEEDED = "SUCCEEDED"
    STATUS_FAILED = "FAILED"

    TERMINAL_STATUSES = {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_TRANSFER_FAILED}

    STATUS_CHOICES = [
        (STATUS_QUEUED, "Queued"),
        (STATUS_TRANSFERRING, "Transferring"),
        (STATUS_TRANSFER_FAILED, "Transfer failed"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCEEDED, "Succeeded"),
        (STATUS_FAILED, "Failed"),
    ]

    execution_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant_id = models.CharField(max_length=128, db_index=True)
    delegate = models.ForeignKey(Delegate, on_delete=models.SET_NULL, null=True, related_name="executions")
    workspace_fixture = models.CharField(max_length=256)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_QUEUED)
    transfer_id = models.CharField(max_length=64, blank=True, default="")
    transfer_attempts = models.IntegerField(default=0)
    output_path = models.CharField(max_length=256, blank=True, default="")
    output_checksum = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.execution_id} [{self.status}]"


class ExecutionLog(models.Model):
    execution = models.ForeignKey(Execution, on_delete=models.CASCADE, related_name="logs")
    seq = models.IntegerField()
    line = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["seq"]


class AuditEvent(models.Model):
    event_type = models.CharField(max_length=64)
    tenant_id = models.CharField(max_length=128, blank=True, default="")
    delegate_id = models.CharField(max_length=64, blank=True, default="")
    execution_id = models.CharField(max_length=64, blank=True, default="")
    detail = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.event_type} @ {self.created_at}"
