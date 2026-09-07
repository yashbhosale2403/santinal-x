import uuid
from django.db import models
from django.conf import settings
from apps.forensic.models import Case

class AuditEvent(models.Model):
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    case = models.ForeignKey(Case, on_delete=models.SET_NULL, null=True, blank=True)
    operation_id = models.CharField(max_length=100, blank=True)
    event_type = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.CharField(max_length=45, blank=True)
    details = models.JSONField(default=dict, blank=True)
    previous_event_hash = models.CharField(max_length=64, default='0' * 64)
    event_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"Audit {self.event_type} @ {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - Hash: {self.event_hash[:12]}..."
