import uuid
from django.db import models
from django.conf import settings
from apps.forensic.models import Case

class Report(models.Model):
    class ReportType(models.TextChoices):
        SANITIZATION_CERTIFICATE = 'SANITIZATION_CERTIFICATE', 'Drive Sanitization Certificate'
        FILE_ERASURE_REPORT = 'FILE_ERASURE_REPORT', 'File & Directory Erasure Report'
        FORENSIC_RECOVERY_REPORT = 'FORENSIC_RECOVERY_REPORT', 'Forensic File Carving & Recovery Report'
        EVIDENCE_INTEGRITY_REPORT = 'EVIDENCE_INTEGRITY_REPORT', 'Evidence Integrity Report'
        CHAIN_OF_CUSTODY_REPORT = 'CHAIN_OF_CUSTODY_REPORT', 'Chain of Custody Report'
        AUDIT_REPORT = 'AUDIT_REPORT', 'System Audit & Tamper Log Report'

    class Format(models.TextChoices):
        PDF = 'PDF', 'PDF Document'
        HTML = 'HTML', 'HTML Web Page'
        JSON = 'JSON', 'JSON Data Export'

    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=30, choices=ReportType.choices)
    title = models.CharField(max_length=255)
    case = models.ForeignKey(Case, on_delete=models.SET_NULL, null=True, blank=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=500)
    report_hash = models.CharField(max_length=64, blank=True)
    format = models.CharField(max_length=10, choices=Format.choices, default=Format.PDF)

    def __str__(self):
        return f"Report {self.title} ({self.report_type}) - Hash: {self.report_hash[:12]}"
