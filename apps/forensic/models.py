import uuid
from django.db import models
from django.conf import settings

class Case(models.Model):
    class Status(models.TextChoices):
        OPEN = 'OPEN', 'Open'
        ACTIVE = 'ACTIVE', 'Active Investigation'
        CLOSED = 'CLOSED', 'Closed'
        ARCHIVED = 'ARCHIVED', 'Archived'

    case_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case_number = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    investigator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='assigned_cases')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.case_number} - {self.title}"

class EvidenceSource(models.Model):
    class SourceType(models.TextChoices):
        FORENSIC_IMAGE = 'FORENSIC_IMAGE', 'Forensic Disk Image (.img/.raw)'
        PHYSICAL_DEVICE = 'PHYSICAL_DEVICE', 'Physical Storage Device'
        FILE_DIRECTORY = 'FILE_DIRECTORY', 'File Directory'
        TEST_MEDIA = 'TEST_MEDIA', 'Synthetic Test Media'

    evidence_id = models.CharField(max_length=50, unique=True)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='evidence_sources')
    name = models.CharField(max_length=200)
    source_type = models.CharField(max_length=30, choices=SourceType.choices, default=SourceType.FORENSIC_IMAGE)
    file_path = models.CharField(max_length=500)
    size_bytes = models.BigIntegerField(default=0)
    sha256_hash = models.CharField(max_length=64, blank=True)
    acquired_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def formatted_size(self):
        gb = self.size_bytes / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.2f} GB"
        mb = self.size_bytes / (1024 ** 2)
        return f"{mb:.2f} MB"

    def __str__(self):
        return f"{self.evidence_id} ({self.name})"

class ChainOfCustodyEvent(models.Model):
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='custody_events')
    evidence_source = models.ForeignKey(EvidenceSource, on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    actor_name = models.CharField(max_length=150)
    action = models.CharField(max_length=200)
    object_description = models.CharField(max_length=255)
    recorded_hash = models.CharField(max_length=64, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Chain of Custody Event: {self.action} on {self.object_description}"
