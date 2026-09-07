import time
from django.test import TransactionTestCase, Client
from django.urls import reverse
from apps.devices.models import StorageDevice
from apps.sanitization.models import SanitizationOperation

class AsyncSanitizationTestCase(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.client = Client()
        self.device = StorageDevice.objects.create(
            device_id='DEV_TEST_001',
            name='Test NVMe Disk',
            media_type='NVME_SSD',
            interface_type='NVME',
            capacity_bytes=1024*1024*5,
            mount_point='demo_data/test_drive.img',
            is_demo_device=True
        )

    def test_start_sanitization_creates_operation(self):
        url = reverse('sanitization_wizard')
        response = self.client.post(url, {
            'device_id': self.device.device_id,
            'method': 'NIST_CLEAR',
            'execution_mode': 'SAFE_TEST_MODE',
            'confirmation_code': f'ERASE {self.device.device_id}',
            'ack_checkbox': 'on',
            'ajax': '1'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['status'], 'SUCCESS')
        op_id = data['operation_id']

        op = SanitizationOperation.objects.get(operation_id=op_id)
        self.assertEqual(op.device, self.device)
        self.assertIn(op.status, ['INITIALIZING', 'DETECTING_DEVICE', 'CHECKING_CAPABILITIES', 'PREPARING', 'SANITIZING', 'VERIFYING', 'COMPLETED'])

    def test_duplicate_sanitization_request_rejected(self):
        SanitizationOperation.objects.create(
            device=self.device,
            status='SANITIZING',
            progress=50
        )
        url = reverse('sanitization_wizard')
        response = self.client.post(url, {
            'device_id': self.device.device_id,
            'method': 'NIST_CLEAR',
            'execution_mode': 'SAFE_TEST_MODE',
            'confirmation_code': f'ERASE {self.device.device_id}',
            'ack_checkbox': 'on',
            'ajax': '1'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['status'], 'ERROR')
        self.assertIn('already in progress', data['error_message'])

    def test_status_api_endpoint(self):
        op = SanitizationOperation.objects.create(
            device=self.device,
            status='SANITIZING',
            progress=45,
            current_stage='SANITIZING',
            status_message='Sanitizing storage blocks...'
        )
        url = reverse('sanitization_status_api', kwargs={'operation_id': op.operation_id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['progress'], 45)
        self.assertEqual(data['current_stage'], 'SANITIZING')

    def test_cancellation_flow(self):
        op = SanitizationOperation.objects.create(
            device=self.device,
            status='SANITIZING',
            progress=40
        )
        url = reverse('sanitization_cancel_api', kwargs={'operation_id': op.operation_id})
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)

        op.refresh_from_db()
        self.assertEqual(op.status, 'CANCELLED')

    def test_background_worker_progress_to_completion(self):
        url = reverse('sanitization_wizard')
        response = self.client.post(url, {
            'device_id': self.device.device_id,
            'method': 'NIST_CLEAR',
            'execution_mode': 'SAFE_TEST_MODE',
            'confirmation_code': f'ERASE {self.device.device_id}',
            'ack_checkbox': 'on',
            'ajax': '1'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        op_id = response.json()['operation_id']

        for _ in range(60):
            op = SanitizationOperation.objects.get(operation_id=op_id)
            if op.status in ['COMPLETED', 'FAILED']:
                break
            time.sleep(0.15)

        op.refresh_from_db()
        self.assertEqual(op.status, 'COMPLETED')
        self.assertEqual(op.progress, 100)
        self.assertEqual(op.verification_status, 'PASS')
        self.assertTrue(op.report_path.endswith('.pdf'))
