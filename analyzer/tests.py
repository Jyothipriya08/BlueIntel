from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from django.contrib.auth.models import User
from analyzer.models import ThreatAnalysisLog, UserSetting, UserNotification
import io

class BlueIntelTests(TestCase):
    databases = {'default', 'malware_sandbox_pool'}

    def setUp(self):
        # Create a test developer user
        self.user, created = User.objects.get_or_create(
            username='developer',
            defaults={'email': 'developer@blueintel.com'}
        )
        # Create default settings
        self.settings, created = UserSetting.objects.get_or_create(
            user=self.user,
            defaults={'theme': 'dark', 'enable_notifications': True}
        )

    def test_upload_unsupported_file(self):
        url = reverse('file_upload_analysis')
        data = {'file': io.BytesIO(b"dummy content"), 'name': 'test.txt'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Unsupported file extension', response.data['error'])

    def test_upload_supported_file(self):
        url = reverse('file_upload_analysis')
        file_content = b"MZ\x90\x00\x03\x00\x00\x00"  # MZ header
        file_obj = io.BytesIO(file_content)
        file_obj.name = 'test.exe'
        data = {'file': file_obj}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], 'PROCESSING')

    def test_get_settings(self):
        url = reverse('api_settings')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['theme'], 'dark')
        self.assertFalse(response.data['vt_key_configured'])

    def test_update_settings(self):
        url = reverse('api_settings')
        payload = {
            'theme': 'cyberpunk',
            'enable_notifications': False,
            'vt_key': 'test_vt_key',
            'claude_key': 'test_claude_key'
        }
        response = self.client.put(url, payload, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['theme'], 'cyberpunk')
        self.assertFalse(response.data['enable_notifications'])
        self.assertTrue(response.data['vt_key_configured'])
        self.assertTrue(response.data['claude_key_configured'])

    def test_dashboard_stats(self):
        # Create a completed analysis log
        ThreatAnalysisLog.objects.create(
            file_name='malware.exe',
            file_size_bytes=1024,
            sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            status='COMPLETED',
            entropy=6.5,
            malware_classification={'verdict': 'MALICIOUS', 'score': 0.85}
        )
        url = reverse('api_dashboard_stats')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_analyzed'], 1)
        self.assertEqual(response.data['malicious'], 1)

    def test_get_notifications(self):
        UserNotification.objects.create(
            user=self.user,
            title="Detonation started",
            message="Active scanner"
        )
        url = reverse('api_notifications')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['title'], "Detonation started")
