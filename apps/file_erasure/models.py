import uuid
from django.db import models
from django.conf import settings

class FileErasureOperation(models.Model):
    class ItemType(models.TextChoices):
        SINGLE_FILE = 'SINGLE_FILE', 'Single File'
        DIRECTORY = 'DIRECTORY', 'Directory / Folder'
        BATCH = 'BATCH', 'Batch Files'

    class ErasureMethod(models.TextChoices):
        ZERO_OVERWRITE = 'ZERO_OVERWRITE', 'Single Pass Zero Fill'
        MULTI_PASS_RANDOM = 'MULTI_PASS_RANDOM', '3-Pass Pseudo-Random Overwrite'
        GUTMANN_SIMULATION = 'GUTMANN_SIMULATION', 'Gutmann Standard Simulation'
        UNLINK_ONLY = 'UNLINK_ONLY', 'Unlink / Truncate Only'

    class ExecutionMode(models.TextChoices):
        DEMO_MODE = 'DEMO_MODE', 'Demo Mode'
        SAFE_TEST_MODE = 'SAFE_TEST_MODE', 'Safe Test Sandbox Mode'
        REAL_MODE = 'REAL_MODE', 'Real File System Erasure'

    operation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    target_path = models.CharField(max_length=500)
    item_type = models.CharField(max_length=20, choices=ItemType.choices, default=ItemType.SINGLE_FILE)
    total_files = models.IntegerField(default=1)
    total_bytes = models.BigIntegerField(default=0)
    erasure_method = models.CharField(max_length=30, choices=ErasureMethod.choices, default=ErasureMethod.ZERO_OVERWRITE)
    execution_mode = models.CharField(max_length=20, choices=ExecutionMode.choices, default=ExecutionMode.DEMO_MODE)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='PENDING')
    verification_status = models.CharField(max_length=20, default='NOT_VERIFIABLE')
    operation_hash = models.CharField(max_length=64, blank=True)
    inventory_metadata = models.JSONField(default=dict, blank=True)
    limitation_warnings = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"File Erasure {self.operation_id} ({self.target_path})"
