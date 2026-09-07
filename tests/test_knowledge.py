from django.test import TestCase, Client
from django.urls import reverse

class KnowledgeSectionsTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    def test_technology_view_status_code(self):
        response = self.client.get('/technology/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Sanitization Decision Engine')
        self.assertContains(response, 'NIST SP 800-88 Rev. 2')

    def test_documentation_view_status_code(self):
        response = self.client.get('/documentation/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Technical Architecture')
        self.assertContains(response, 'SIH26149')

    def test_technology_api_endpoint(self):
        response = self.client.get('/api/technology/')
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertEqual(json_data['status'], 'success')
        self.assertEqual(json_data['hashing_algorithm'], 'SHA-256')

    def test_documentation_api_endpoint(self):
        response = self.client.get('/api/documentation/')
        self.assertEqual(response.status_code, 200)
        json_data = response.json()
        self.assertEqual(json_data['status'], 'success')
        self.assertIn('Sanitization Decision Engine', json_data['content'])
