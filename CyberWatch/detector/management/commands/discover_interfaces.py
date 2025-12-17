"""
Django management command to discover network interfaces
"""
from django.core.management.base import BaseCommand
from detector.network_discovery import discover_network_interfaces


class Command(BaseCommand):
    help = 'Automatically discover and configure network interfaces'

    def handle(self, *args, **options):
        self.stdout.write('Discovering network interfaces...')
        
        count = discover_network_interfaces()
        
        if count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully discovered {count} network interface(s)')
            )
        else:
            self.stdout.write(
                self.style.WARNING('No new network interfaces found')
            )
