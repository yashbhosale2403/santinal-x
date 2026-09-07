import os
import io
import zipfile
import hashlib
from django.core.management.base import BaseCommand
from apps.authentication.models import User
from apps.forensic.models import Case, EvidenceSource, ChainOfCustodyEvent
from apps.devices.models import StorageDevice
from workers.device_worker.detector import DeviceDetector
from apps.audit.utils import AuditLogger

class Command(BaseCommand):
    help = 'Creates synthetic demo data, test_drive.img forensic image, admin user, case, and evidence'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Initializing SENTINEL-X Demo Environment..."))

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
        demo_dir = os.path.join(base_dir, 'demo_data')
        os.makedirs(demo_dir, exist_ok=True)
        img_path = os.path.join(demo_dir, 'test_drive.img')

        # 1. Create Admin User
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@sentinelx.gov',
                'role': User.Role.ADMIN,
                'is_staff': True,
                'is_superuser': True
            }
        )
        if created:
            admin_user.set_password('admin123')
            admin_user.save()
            self.stdout.write(self.style.SUCCESS("Created admin user: admin / admin123"))

        # 2. Build Synthetic Forensic Image (test_drive.img) with embedded files
        img_size = 20 * 1024 * 1024 # 20 MB image
        buf = bytearray(b'\x00' * img_size)

        # Embedded Artifact 1: JPEG Image
        jpeg_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\x27 \x22#\x1c\x1c(7(-01232\x1c\x1966?89:;\xFF\xC0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00\xFF\xC4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00\x7F\x00\xFF\xD9'
        offset1 = 512 * 1024 # Offset 512KB
        buf[offset1 : offset1 + len(jpeg_data)] = jpeg_data

        # Embedded Artifact 2: PDF Document
        pdf_data = b'%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kinds [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000120 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n'
        offset2 = 2 * 1024 * 1024 # Offset 2MB
        buf[offset2 : offset2 + len(pdf_data)] = pdf_data

        # Embedded Artifact 3: DOCX Zip Container
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, 'w') as zf:
            zf.writestr('[Content_Types].xml', '<?xml version="1.0"?><Types></Types>')
            zf.writestr('word/document.xml', '<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>CONFIDENTIAL FORENSIC EVIDENCE DOC</w:t></w:r></w:p></w:body></w:document>')
        docx_data = zip_buf.getvalue()
        offset3 = 5 * 1024 * 1024 # Offset 5MB
        buf[offset3 : offset3 + len(docx_data)] = docx_data

        # Embedded Artifact 4: TXT File
        txt_data = b'SENTINEL-X SIH26149 FORENSIC TEST LOG\nTimestamp: 2026-09-07\nEvidence Classification: Top Secret\nOperator: Investigator Admin\n'
        offset4 = 8 * 1024 * 1024 # Offset 8MB
        buf[offset4 : offset4 + len(txt_data)] = txt_data

        with open(img_path, 'wb') as f:
            f.write(buf)

        img_hash = hashlib.sha256(buf).hexdigest()
        self.stdout.write(self.style.SUCCESS(f"Created synthetic forensic image: {img_path} ({img_size/(1024*1024):.0f}MB, SHA-256: {img_hash[:16]}...)"))

        # 3. Create Case & Evidence Records
        case, _ = Case.objects.get_or_create(
            case_number='CASE-2026-001',
            defaults={
                'title': 'Operation CyberSanitize - Evidence Drive Investigation',
                'description': 'SIH 2026 Problem Statement 26149 Verification Case',
                'investigator': admin_user
            }
        )

        ev, _ = EvidenceSource.objects.get_or_create(
            evidence_id='EVIDENCE-001',
            defaults={
                'case': case,
                'name': 'Seized Media Forensic Image (test_drive.img)',
                'source_type': EvidenceSource.SourceType.TEST_MEDIA,
                'file_path': img_path,
                'size_bytes': img_size,
                'sha256_hash': img_hash,
                'acquired_by': admin_user
            }
        )

        ChainOfCustodyEvent.objects.get_or_create(
            case=case,
            evidence_source=ev,
            action='EVIDENCE_ACQUIRED',
            defaults={
                'actor_name': 'Investigator Admin',
                'object_description': 'EVIDENCE-001 (test_drive.img)',
                'recorded_hash': img_hash,
                'notes': 'Acquired bit-stream image file for SIH26149 demonstration.'
            }
        )

        # 4. Refresh Devices DB
        detected = DeviceDetector.detect_all_devices()
        for d in detected:
            StorageDevice.objects.update_or_create(
                device_id=d['device_id'],
                defaults=d
            )

        # 5. Audit Event
        AuditLogger.log_event('DEMO_ENVIRONMENT_CREATED', user=admin_user, case=case, details={'img_hash': img_hash})

        self.stdout.write(self.style.SUCCESS("DEMO ENVIRONMENT CREATED SUCCESSFULLY!"))
