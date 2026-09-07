import uuid
from django.db import models
from django.conf import settings
from apps.devices.models import StorageDevice
from apps.forensic.models import Case

class SanitizationOperation(models.Model):
    class Method(models.TextChoices):
        NIST_CLEAR = 'NIST_CLEAR', 'NIST SP 800-88 Clear (Logical Overwrite)'
        NIST_PURGE = 'NIST_PURGE', 'NIST SP 800-88 Purge (Device Sanitize Command)'
        CRYPTOGRAPHIC_ERASE = 'CRYPTOGRAPHIC_ERASE', 'Cryptographic Erase (CE / Sanitize)'
        DOD_3_PASS = 'DOD_3_PASS', 'DoD 5220.22-M (3-Pass Simulation)'
        ZERO_FILL = 'ZERO_FILL', 'Single-Pass Zero Fill'
        RANDOM_PASS = 'RANDOM_PASS', 'Random Data Pass'

    class ExecutionMode(models.TextChoices):
        DEMO_MODE = 'DEMO_MODE', 'Demo Mode (Safe Synthetic Image)'
        SAFE_TEST_MODE = 'SAFE_TEST_MODE', 'Safe Test Mode (Sandbox File/Drive)'
        REAL_MODE = 'REAL_MODE', 'Real Mode (Destructive Hardware Access)'

    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        INITIALIZING = 'INITIALIZING', 'Initializing'
        DETECTING_DEVICE = 'DETECTING_DEVICE', 'Detecting Device'
        CHECKING_CAPABILITIES = 'CHECKING_CAPABILITIES', 'Checking Capabilities'
        PREPARING = 'PREPARING', 'Preparing'
        SANITIZING = 'SANITIZING', 'Sanitizing'
        VERIFYING = 'VERIFYING', 'Verifying'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'
        CANCELLED = 'CANCELLED', 'Cancelled'

    class VerificationStatus(models.TextChoices):
        PASS = 'PASS', 'PASS (Verification Succeeded)'
        FAIL = 'FAIL', 'FAIL (Verification Failed)'
        PARTIAL = 'PARTIAL', 'PARTIAL Verification'
        NOT_VERIFIABLE = 'NOT_VERIFIABLE', 'NOT VERIFIABLE'

    operation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(StorageDevice, on_delete=models.CASCADE, related_name='sanitization_operations')
    method = models.CharField(max_length=35, choices=Method.choices, default=Method.NIST_CLEAR)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    execution_mode = models.CharField(max_length=20, choices=ExecutionMode.choices, default=ExecutionMode.DEMO_MODE)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=25, choices=Status.choices, default=Status.PENDING)
    progress = models.IntegerField(default=0)
    current_stage = models.CharField(max_length=50, default='INITIALIZING')
    status_message = models.CharField(max_length=255, default='Initializing sanitization...')
    bytes_processed = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    verification_status = models.CharField(max_length=20, choices=VerificationStatus.choices, default=VerificationStatus.NOT_VERIFIABLE)
    error_message = models.TextField(blank=True)
    report_path = models.CharField(max_length=500, blank=True)
    operation_hash = models.CharField(max_length=64, blank=True)
    assurance_level = models.CharField(max_length=50, default='CLEAR')
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"Sanitization {self.operation_id} ({self.device.name}) - {self.status}"
