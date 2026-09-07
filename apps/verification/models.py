import uuid
from django.db import models
from django.conf import settings

class VerificationResult(models.Model):
    class TargetType(models.TextChoices):
        SANITIZATION = 'SANITIZATION', 'Sanitization Operation'
        FILE_ERASURE = 'FILE_ERASURE', 'File Erasure Operation'
        RECOVERY_FILE = 'RECOVERY_FILE', 'Recovered File Verification'
        EVIDENCE = 'EVIDENCE', 'Evidence Image Hashing'

    class Status(models.TextChoices):
        PASS = 'PASS', 'PASS'
        FAIL = 'FAIL', 'FAIL'
        PARTIAL = 'PARTIAL', 'PARTIAL'
        NOT_VERIFIABLE = 'NOT_VERIFIABLE', 'NOT VERIFIABLE'

    result_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_type = models.CharField(max_length=25, choices=TargetType.choices)
    target_id = models.CharField(max_length=100)
    verification_method = models.CharField(max_length=150)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NOT_VERIFIABLE)
    checked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(default=dict, blank=True)
    verification_hash = models.CharField(max_length=64, blank=True)

    def __str__(self):
        return f"Verification {self.result_id} - {self.target_type}:{self.target_id} [{self.status}]"
