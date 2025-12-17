from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from detector.models import DetectedThreat


class Alert(models.Model):
    """Alert instances with severity, status, acknowledgment"""
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('ACKNOWLEDGED', 'Acknowledged'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    threat = models.ForeignKey(DetectedThreat, on_delete=models.CASCADE, related_name='alerts')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    acknowledged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='acknowledged_alerts')
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')
    resolved_at = models.DateTimeField(null=True, blank=True)
    email_sent = models.BooleanField(default=False)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_alert'
        verbose_name = 'Alert'
        verbose_name_plural = 'Alerts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at']),
        ]
    
    def __str__(self):
        return f"Alert #{self.id}: {self.threat.get_threat_type_display()} - {self.status}"
    
    def acknowledge(self, user):
        """Acknowledge this alert"""
        self.status = 'ACKNOWLEDGED'
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.save()
    
    def resolve(self, user):
        """Resolve this alert"""
        self.status = 'RESOLVED'
        self.resolved_by = user
        self.resolved_at = timezone.now()
        self.save()


class AlertRule(models.Model):
    """Configurable alert rules and thresholds"""
    name = models.CharField(max_length=200)
    description = models.TextField()
    threat_type = models.CharField(max_length=20, choices=DetectedThreat.THREAT_TYPES)
    min_severity = models.CharField(max_length=10, choices=DetectedThreat.SEVERITY_LEVELS, default='WARNING')
    is_active = models.BooleanField(default=True)
    send_email = models.BooleanField(default=True)
    auto_block = models.BooleanField(default=False)
    threshold_count = models.IntegerField(default=1, help_text="Number of detections before triggering alert")
    threshold_window = models.IntegerField(default=300, help_text="Time window in seconds")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_rule'
        verbose_name = 'Alert Rule'
        verbose_name_plural = 'Alert Rules'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class NotificationChannel(models.Model):
    """Email, webhook, or other notification methods"""
    CHANNEL_TYPES = [
        ('EMAIL', 'Email'),
        ('WEBHOOK', 'Webhook'),
        ('SMS', 'SMS'),
    ]
    
    name = models.CharField(max_length=200)
    channel_type = models.CharField(max_length=20, choices=CHANNEL_TYPES)
    is_active = models.BooleanField(default=True)
    configuration = models.JSONField(default=dict, help_text="Channel-specific configuration")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'alerts_notification_channel'
        verbose_name = 'Notification Channel'
        verbose_name_plural = 'Notification Channels'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"


class AlertHistory(models.Model):
    """Historical alert data for analysis"""
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='history')
    action = models.CharField(max_length=100)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'alerts_history'
        verbose_name = 'Alert History'
        verbose_name_plural = 'Alert Histories'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.action} on Alert #{self.alert.id}"


class EmailNotification(models.Model):
    """Track email notifications sent"""
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='emails')
    recipient = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'alerts_email_notification'
        verbose_name = 'Email Notification'
        verbose_name_plural = 'Email Notifications'
        ordering = ['-sent_at']
    
    def __str__(self):
        status = "Sent" if self.success else "Failed"
        return f"{status}: {self.subject} to {self.recipient}"
