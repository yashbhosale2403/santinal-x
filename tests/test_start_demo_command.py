from django.core.management import get_commands
from django.test import SimpleTestCase


class DemoBootstrapCommandTest(SimpleTestCase):
    def test_start_demo_command_registered(self):
        self.assertIn('start_demo', get_commands())
