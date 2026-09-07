from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'ADMIN', 'Administrator'
        INVESTIGATOR = 'INVESTIGATOR', 'Forensic Investigator'
        OPERATOR = 'OPERATOR', 'Sanitization Operator'
        VIEWER = 'VIEWER', 'Auditor / Viewer'

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.INVESTIGATOR)
    department = models.CharField(max_length=100, blank=True)
    badge_id = models.CharField(max_length=50, blank=True)

    def is_admin(self):
        return self.role == self.Role.ADMIN or self.is_superuser

    def is_investigator(self):
        return self.role in [self.Role.ADMIN, self.Role.INVESTIGATOR]

    def is_operator(self):
        return self.role in [self.Role.ADMIN, self.Role.OPERATOR]

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
