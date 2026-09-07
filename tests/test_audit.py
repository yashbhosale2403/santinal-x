from django.test import TestCase
from apps.audit.models import AuditEvent
from apps.audit.utils import AuditLogger

class AuditTestCase(TestCase):
    def test_audit_hash_chain_integrity(self):
        # 1. Log sequential events
        e1 = AuditLogger.log_event('TEST_EVENT_1', details={'step': 1})
        e2 = AuditLogger.log_event('TEST_EVENT_2', details={'step': 2})
        e3 = AuditLogger.log_event('TEST_EVENT_3', details={'step': 3})

        # 2. Verify intact chain -> GREEN
        res = AuditLogger.verify_audit_integrity()
        self.assertEqual(res['status'], 'GREEN')

        # 3. Tamper with event 2
        e2.event_hash = "0" * 64
        e2.save()

        # 4. Verify tampered chain -> RED
        res_tampered = AuditLogger.verify_audit_integrity()
        self.assertEqual(res_tampered['status'], 'RED')

        # 5. Repair/reset audit chain -> return to GREEN
        repaired = AuditLogger.repair_audit_integrity()
        self.assertGreater(repaired, 0)
        res_repaired = AuditLogger.verify_audit_integrity()
        self.assertEqual(res_repaired['status'], 'GREEN')

