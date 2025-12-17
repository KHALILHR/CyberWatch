from django.apps import AppConfig


class DetectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'detector'
    verbose_name = 'Network Threat Detector'
    
    def ready(self):
        """Import signals when app is ready"""
        import detector.signals  # noqa
