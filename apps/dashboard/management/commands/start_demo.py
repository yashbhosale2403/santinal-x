from django.core.management import BaseCommand, call_command


class Command(BaseCommand):
    help = 'Bootstrap the database, create demo data, and launch the SENTINEL-X demo server.'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='127.0.0.1', help='Hostname to bind the development server to.')
        parser.add_argument('--port', type=int, default=8000, help='Port to bind the development server to.')

    def handle(self, *args, **options):
        self.stdout.write(self.style.HTTP_INFO('Bootstrapping SENTINEL-X demo environment...'))
        call_command('migrate', interactive=False, verbosity=1)
        call_command('create_demo_environment', verbosity=1)

        host = options['host']
        port = options['port']
        self.stdout.write(
            self.style.SUCCESS(f'STARTING SENTINEL-X on http://{host}:{port} (login: admin / admin123)')
        )
        call_command('runserver', f'{host}:{port}', use_reloader=False)
