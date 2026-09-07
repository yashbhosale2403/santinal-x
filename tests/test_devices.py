from django.test import TestCase
from workers.device_worker.detector import DeviceDetector
from workers.sanitization_worker.policy import SanitizationPolicyEngine

class DeviceTestCase(TestCase):
    def test_device_discovery(self):
        devices = DeviceDetector.detect_all_devices()
        self.assertIsInstance(devices, list)

    def test_nist_policy_engine_hdd(self):
        policy = SanitizationPolicyEngine.evaluate_policy('HDD', 'SATA', {'logical_overwrite': True})
        self.assertEqual(policy['recommended_method'], 'NIST_CLEAR')
        self.assertEqual(policy['assurance_level'], 'CLEAR')

    def test_nist_policy_engine_nvme(self):
        policy = SanitizationPolicyEngine.evaluate_policy('NVME_SSD', 'NVME', {'cryptographic_erase': True}, is_encrypted=True)
        self.assertEqual(policy['recommended_method'], 'CRYPTOGRAPHIC_ERASE')
        self.assertEqual(policy['assurance_level'], 'PURGE')
