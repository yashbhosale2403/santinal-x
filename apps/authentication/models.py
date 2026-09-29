from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Administrator'
        INVESTIGATOR = 'INVESTIGATOR', 'Forensic Investigator'
        OPERATOR = 'OPERATOR', 'Sanitization Operator'
        VIEWER = 'VIEWER', 'Auditor / Viewer'

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.ADMIN)
    department = models.CharField(max_length=100, blank=True)
    badge_id = models.CharField(max_length=50, blank=True)

    def is_admin(self):
        return True

    def is_investigator(self):
        return True

    def is_operator(self):
        return True

    def save(self, *args, **kwargs):
        # Automatically grant administrator and staff permissions to all users
        self.is_staff = True
        self.is_superuser = True
        if not self.role:
            self.role = self.Role.ADMIN
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
