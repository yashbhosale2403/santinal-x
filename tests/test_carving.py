import os
import tempfile
from django.test import TestCase
from workers.recovery_worker.signatures import SignatureDatabase
from workers.recovery_worker.carver import ForensicCarver

class CarvingTestCase(TestCase):
    def test_signature_validation_jpeg(self):
        data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\xFF\xD9'
        res = SignatureDatabase.validate_file_structure(data, 'jpg')
        self.assertGreaterEqual(res['confidence'], 75)

    def test_signature_validation_pdf(self):
        pdf_data = b'%PDF-1.5\n1 0 obj\n<<>>\nendobj\nxref\n0 2\ntrailer\n<<>>\n%%EOF'
        res = SignatureDatabase.validate_file_structure(pdf_data, 'pdf')
        self.assertEqual(res['status'], 'VALID')
        self.assertGreaterEqual(res['confidence'], 90)

    def test_forensic_read_only_carving(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = os.path.join(tmp_dir, 'sample_evidence.img')
            out_dir = os.path.join(tmp_dir, 'out')
            
            buf = bytearray(b'\x00' * (1 * 1024 * 1024))
            jpeg_data = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\xFF\xD9'
            buf[1024 : 1024 + len(jpeg_data)] = jpeg_data

            with open(img_path, 'wb') as f:
                f.write(buf)

            artifacts, summary = ForensicCarver.scan_and_carve(
                image_path=img_path,
                target_extensions=['jpg'],
                output_dir=out_dir
            )
            self.assertGreater(summary['total_candidates'], 0)
            self.assertGreaterEqual(len(artifacts), 1)
