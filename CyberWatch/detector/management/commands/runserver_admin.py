from django.core.management.base import BaseCommand
from django.core.management import call_command
import platform
import ctypes
import sys
import os
import subprocess


class Command(BaseCommand):
    help = 'Run the Django development server with Administrator privileges on Windows'

    def add_arguments(self, parser):
        parser.add_argument('runserver_args', nargs='*')

    def _is_windows_admin(self):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def handle(self, *args, **options):
        runserver_args = options.get('runserver_args') or []

        if platform.system().lower().startswith('win') and not self._is_windows_admin():
            manage_py = os.path.abspath(os.path.join(os.getcwd(), 'manage.py'))
            if not os.path.exists(manage_py):
                manage_py = os.path.abspath('manage.py')

            arg_list = [manage_py, 'runserver', *runserver_args]
            args_str = subprocess.list2cmdline(arg_list)

            rc = ctypes.windll.shell32.ShellExecuteW(
                None,
                'runas',
                sys.executable,
                args_str,
                os.getcwd(),
                1,
            )

            if rc <= 32:
                self.stderr.write(self.style.ERROR('UAC elevation was cancelled or failed.'))
            return

        call_command('runserver', *runserver_args)
