from django.db import models

class StorageDevice(models.Model):
    class InterfaceType(models.TextChoices):
        SATA = 'SATA', 'SATA Interface'
        NVME = 'NVME', 'NVMe Interface'
        USB = 'USB', 'USB Flash / External'
        SD = 'SD', 'SD / MicroSD Card'
        VIRTUAL = 'VIRTUAL', 'Virtual Disk / Image'
        UNKNOWN = 'UNKNOWN', 'Unknown'

    class MediaType(models.TextChoices):
        HDD = 'HDD', 'Hard Disk Drive (Magnetic)'
        SATA_SSD = 'SATA_SSD', 'SATA Solid State Drive'
        NVME_SSD = 'NVME_SSD', 'NVMe Solid State Drive'
        USB_FLASH = 'USB_FLASH', 'USB Flash Storage'
        SD_CARD = 'SD_CARD', 'SD Memory Card'
        TEST_IMAGE = 'TEST_IMAGE', 'Synthetic Test Image'

    class HealthStatus(models.TextChoices):
        HEALTHY = 'HEALTHY', 'Healthy / PASSED'
        WARNING = 'WARNING', 'Warning'
        CRITICAL = 'CRITICAL', 'Critical Failure'
        UNKNOWN = 'UNKNOWN', 'Unknown'

    device_id = models.CharField(max_length=100, primary_key=True)
    name = models.CharField(max_length=200)
    serial_number = models.CharField(max_length=150, blank=True)
    model = models.CharField(max_length=200, blank=True)
    manufacturer = models.CharField(max_length=150, blank=True)
    capacity_bytes = models.BigIntegerField(default=0)
    interface_type = models.CharField(max_length=20, choices=InterfaceType.choices, default=InterfaceType.UNKNOWN)
    media_type = models.CharField(max_length=20, choices=MediaType.choices, default=MediaType.HDD)
    filesystem = models.CharField(max_length=50, blank=True)
    removable = models.BooleanField(default=False)
    readonly = models.BooleanField(default=False)
    detected_capabilities = models.JSONField(default=dict, blank=True)
    health_status = models.CharField(max_length=20, choices=HealthStatus.choices, default=HealthStatus.HEALTHY)
    mount_point = models.CharField(max_length=255, blank=True)
    is_demo_device = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_os_drive(self):
        import os
        import platform
        sys_drive = os.environ.get('SystemDrive', 'C:').upper().rstrip('\\')

        mp = (self.mount_point or '').strip().upper()
        if mp:
            if platform.system() == 'Windows':
                if mp.startswith(sys_drive) or mp.startswith('C:'):
                    return True
            else:
                if mp == '/' or mp.startswith('/BOOT') or mp.startswith('/ROOT'):
                    return True

        name_upper = (self.name or '').upper()
        dev_id_upper = (self.device_id or '').upper()
        if 'C:' in name_upper or 'C:\\' in name_upper or '_C_' in dev_id_upper or '[C:' in name_upper or '[C,' in name_upper:
            return True

        return False

    def formatted_capacity(self):
        gb = self.capacity_bytes / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.2f} GB"
        mb = self.capacity_bytes / (1024 ** 2)
        return f"{mb:.2f} MB"

    def __str__(self):
        return f"{self.name} ({self.model or self.device_id}) - {self.formatted_capacity()}"
