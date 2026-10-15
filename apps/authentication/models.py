from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Administrator'
        INVESTIGATOR = 'INVESTIGATOR', 'Forensic Investigator'
        OPERATOR = 'OPERATOR', 'Sanitization Operator'
        VIEWER = 'VIEWER', 'Auditor / Viewer'

    # Public registrations start with the least-privileged role.
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)
    department = models.CharField(max_length=100, blank=True)
    badge_id = models.CharField(max_length=50, blank=True)

    def is_admin(self):
        return bool(self.is_superuser or self.role == self.Role.ADMIN)

    def is_investigator(self):
        return bool(self.is_superuser or self.role == self.Role.INVESTIGATOR)

    def is_operator(self):
        return bool(self.is_superuser or self.role == self.Role.OPERATOR)

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
