import os
import tempfile
import hashlib
from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.forensic.models import Case, EvidenceSource
from apps.recovery.models import RecoveryOperation, RecoveredFile
from apps.ledger.models import LedgerEntry
from apps.reports.models import Report
from workers.recovery_worker.engine import RecoveryEngine
from workers.recovery_worker.image_reader import StreamingImageReader
from workers.recovery_worker.partition import PartitionDetector
from workers.recovery_worker.filesystem import FilesystemDetector

User = get_user_model()

class AdvancedRecoveryEngineTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testinvestigator", password="password123")
        self.case = Case.objects.create(
            case_number="CASE-TEST-2026",
            title="Test Forensic Case",
            investigator=self.user
        )
        
        # Create a synthetic evidence disk image containing sample files
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.img_path = os.path.join(self.tmp_dir.name, 'synthetic_evidence.img')
        
        # Build synthetic 10MB image buffer
        buf = bytearray(b'\x00' * (10 * 1024 * 1024))

        # Add MBR partition signature at sector 0
        buf[510:512] = b'\x55\xAA'

        # Inject sample JPEG
        jpeg_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\xFF\xD9'
        buf[10000 : 10000 + len(jpeg_data)] = jpeg_data

        # Inject sample PDF
        pdf_data = b'%PDF-1.5\n1 0 obj\n<<>>\nendobj\nxref\n0 2\ntrailer\n<<>>\n%%EOF'
        buf[50000 : 50000 + len(pdf_data)] = pdf_data

        with open(self.img_path, 'wb') as f:
            f.write(buf)

        self.evidence = EvidenceSource.objects.create(
            case=self.case,
            name="synthetic_evidence.img",
            file_path=self.img_path,
            size_bytes=len(buf),
            sha256_hash=hashlib.sha256(buf).hexdigest()
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_read_only_source_preservation(self):
        """CRITICAL TEST: Ensures source image hash before and after recovery is 100% identical."""
        hash_before = StreamingImageReader.calculate_sha256(self.img_path)
        
        out_dir = os.path.join(self.tmp_dir.name, 'out_test')
        artifacts, summary = RecoveryEngine.run(
            image_path=self.img_path,
            recovery_mode='DEEP',
            target_extensions=['jpg', 'pdf'],
            output_dir=out_dir
        )

        hash_after = StreamingImageReader.calculate_sha256(self.img_path)
        self.assertEqual(hash_before, hash_after)
        self.assertEqual(summary['evidence_sha256'], hash_before)

    def test_partition_and_filesystem_detection(self):
        parts = PartitionDetector.detect_partitions(self.img_path)
        self.assertGreater(len(parts), 0)
        
        fs_info = FilesystemDetector.detect_filesystem(self.img_path)
        self.assertIn('filesystem', fs_info)

    def test_multi_mode_recovery(self):
        out_dir = os.path.join(self.tmp_dir.name, 'out_modes')

        # Test DEEP mode
        artifacts_deep, summary_deep = RecoveryEngine.run(
            image_path=self.img_path,
            recovery_mode='DEEP',
            target_extensions=['jpg', 'pdf'],
            output_dir=out_dir
        )
        self.assertGreaterEqual(len(artifacts_deep), 2)
        self.assertEqual(summary_deep['recovery_mode'], 'DEEP')

        # Test MAXIMUM mode
        artifacts_max, summary_max = RecoveryEngine.run(
            image_path=self.img_path,
            recovery_mode='MAXIMUM',
            target_extensions=['jpg', 'pdf'],
            output_dir=out_dir
        )
        self.assertGreaterEqual(len(artifacts_max), 2)
        self.assertEqual(summary_max['recovery_mode'], 'MAXIMUM')

    def test_web_recovery_view_flow_with_ledger_and_audit(self):
        """Tests Django view execution, PDF report generation, Audit event, and LedgerEntry creation."""
        from django.test import Client
        client = Client()

        response = client.post('/recovery/', {
            'evidence_id': str(self.evidence.evidence_id),
            'case_id': str(self.case.case_id),
            'recovery_mode': 'DEEP',
            'cat_images': 'on',
            'cat_docs': 'on',
            'opt_validation': 'on',
            'opt_dedup': 'on'
        })
        self.assertEqual(response.status_code, 302)

        op = RecoveryOperation.objects.filter(evidence_source=self.evidence).first()
        self.assertIsNotNone(op)
        self.assertEqual(op.status, 'COMPLETED')

        # Verify RecoveredFiles
        rec_files = op.recovered_files.all()
        self.assertGreater(rec_files.count(), 0)

        # Verify Report creation
        rep = Report.objects.filter(file_path__contains=str(op.operation_id)).first()
        self.assertIsNotNone(rep)

        # Verify Immutable Ledger Entry creation
        ledger = LedgerEntry.objects.filter(operation_id=str(op.operation_id)).first()
        self.assertIsNotNone(ledger)
        self.assertEqual(ledger.verification_status, 'VERIFIED')
        self.assertEqual(ledger.report_hash, rep.report_hash)
