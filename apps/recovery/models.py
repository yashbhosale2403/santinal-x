import uuid
from django.db import models
from django.conf import settings
from apps.forensic.models import Case, EvidenceSource

class RecoveryOperation(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        SCANNING = 'SCANNING', 'Scanning Evidence Image'
        CARVING = 'CARVING', 'Carving & Extraction'
        VALIDATING = 'VALIDATING', 'Validating Recovered Candidates'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'

    class RecoveryMode(models.TextChoices):
        QUICK = 'QUICK', 'Quick Recovery (Filesystem Metadata)'
        DEEP = 'DEEP', 'Deep Recovery (Metadata + Carving + Validation)'
        MAXIMUM = 'MAXIMUM', 'Maximum Recovery (Metadata + Carving + Fragments + Fusion)'

    operation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='recovery_operations')
    evidence_source = models.ForeignKey(EvidenceSource, on_delete=models.CASCADE, related_name='recovery_operations')
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    recovery_mode = models.CharField(max_length=20, choices=RecoveryMode.choices, default=RecoveryMode.DEEP)
    selected_types = models.JSONField(default=list, help_text="Selected file extensions e.g. ['jpg', 'pdf', 'docx']")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    current_phase = models.CharField(max_length=100, default='Completed')
    progress_percent = models.IntegerField(default=100)
    total_scanned_bytes = models.BigIntegerField(default=0)
    candidates_found = models.IntegerField(default=0)
    valid_files_count = models.IntegerField(default=0)
    operation_hash = models.CharField(max_length=64, blank=True)
    methods_attempted = models.JSONField(default=list)
    methods_completed = models.JSONField(default=list)
    methods_skipped = models.JSONField(default=list)
    failure_details = models.TextField(blank=True)

    def __str__(self):
        return f"Recovery {self.operation_id} [{self.recovery_mode}] on Case {self.case.case_number}"

class RecoveredFile(models.Model):
    class ValidationStatus(models.TextChoices):
        VALID = 'VALID', 'Valid Structure & Decoded'
        PARTIALLY_VALID = 'PARTIALLY_VALID', 'Partially Valid / Truncated'
        CORRUPTED = 'CORRUPTED', 'Corrupted Header/Payload'
        INVALID = 'INVALID', 'Invalid / False Positive'
        UNKNOWN = 'UNKNOWN', 'Unknown'

    class Classification(models.TextChoices):
        IMAGE = 'IMAGE', 'Image File'
        DOCUMENT = 'DOCUMENT', 'Document / PDF / Office'
        AUDIO = 'AUDIO', 'Audio File'
        VIDEO = 'VIDEO', 'Video File'
        ARCHIVE = 'ARCHIVE', 'Archive / ZIP'
        TEXT = 'TEXT', 'Text Document'
        EXECUTABLE = 'EXECUTABLE', 'Executable / Binary'
        OTHER = 'OTHER', 'Other Artifact'

    recovery_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    operation = models.ForeignKey(RecoveryOperation, on_delete=models.CASCADE, related_name='recovered_files')
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='recovered_files')
    evidence_source = models.ForeignKey(EvidenceSource, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255, blank=True)
    original_path = models.CharField(max_length=500, blank=True)
    detected_type = models.CharField(max_length=20)
    mime_type = models.CharField(max_length=100)
    size_bytes = models.BigIntegerField(default=0)
    byte_offset = models.BigIntegerField(default=0)
    sector_number = models.BigIntegerField(default=0)
    sector_offset = models.BigIntegerField(default=0)  # Preserved for backward compatibility
    confidence_score = models.IntegerField(default=0, help_text="Analytical score 0 to 100")
    carving_method = models.CharField(max_length=100, default='HEADER_FOOTER_MATCH')
    recovery_source = models.CharField(max_length=100, default='Signature Carving')
    deleted_status = models.BooleanField(default=True)
    validation_status = models.CharField(max_length=20, choices=ValidationStatus.choices, default=ValidationStatus.UNKNOWN)
    validation_details = models.TextField(blank=True)
    fragment_count = models.IntegerField(default=1)
    fragments_missing = models.IntegerField(default=0)
    reconstruction_status = models.CharField(max_length=30, blank=True)
    sha256_hash = models.CharField(max_length=64, blank=True)
    output_path = models.CharField(max_length=500)
    classification = models.CharField(max_length=20, choices=Classification.choices, default=Classification.OTHER)
    created_at = models.DateTimeField(auto_now_add=True)

    def confidence_label(self):
        s = self.confidence_score
        if s >= 90:
            return "Very High"
        elif s >= 75:
            return "High"
        elif s >= 50:
            return "Medium"
        elif s >= 25:
            return "Low"
        return "Very Low"

    def display_name(self):
        return self.original_filename if self.original_filename else self.filename

    def __str__(self):
        return f"{self.display_name()} ({self.detected_type}) - Score: {self.confidence_score}%"
