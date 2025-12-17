from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import json


class Report(models.Model):
    """Generated reports with metadata"""
    REPORT_TYPES = [
        ('DAILY', 'Daily Report'),
        ('WEEKLY', 'Weekly Report'),
        ('MONTHLY', 'Monthly Report'),
        ('CUSTOM', 'Custom Report'),
    ]
    
    FORMAT_CHOICES = [
        ('PDF', 'PDF'),
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
        ('HTML', 'HTML'),
    ]
    
    title = models.CharField(max_length=255)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES, default='CUSTOM')
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='PDF')
    description = models.TextField(blank=True)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    file_path = models.FileField(upload_to='reports/', blank=True)
    file_size = models.IntegerField(default=0, help_text="File size in bytes")
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    is_scheduled = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'reports_report'
        verbose_name = 'Report'
        verbose_name_plural = 'Reports'
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['-generated_at']),
            models.Index(fields=['report_type', '-generated_at']),
        ]
    
    def __str__(self):
        return f"{self.title} ({self.format}) - {self.generated_at.strftime('%Y-%m-%d')}"


class LogEntry(models.Model):
    """Structured JSON/text log entries"""
    LOG_LEVELS = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    level = models.CharField(max_length=10, choices=LOG_LEVELS, default='INFO')
    module = models.CharField(max_length=100)
    message = models.TextField()
    data = models.JSONField(default=dict, blank=True, help_text="Structured log data")
    traceback = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'reports_log_entry'
        verbose_name = 'Log Entry'
        verbose_name_plural = 'Log Entries'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['level', '-created_at']),
            models.Index(fields=['module', '-created_at']),
        ]
    
    def __str__(self):
        return f"[{self.level}] {self.module}: {self.message[:50]}"


class ReportTemplate(models.Model):
    """Customizable report templates"""
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    template_type = models.CharField(max_length=20, choices=Report.REPORT_TYPES)
    configuration = models.JSONField(default=dict, help_text="Template configuration and settings")
    is_default = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'reports_template'
        verbose_name = 'Report Template'
        verbose_name_plural = 'Report Templates'
        ordering = ['name']
    
    def __str__(self):
        return self.name


class ExportJob(models.Model):
    """Asynchronous export job tracking"""
    JOB_STATUS = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]
    
    job_id = models.CharField(max_length=100, unique=True)
    export_type = models.CharField(max_length=20)
    parameters = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=JOB_STATUS, default='PENDING')
    progress = models.IntegerField(default=0)
    result_file = models.FileField(upload_to='exports/', blank=True)
    error_message = models.TextField(blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'reports_export_job'
        verbose_name = 'Export Job'
        verbose_name_plural = 'Export Jobs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.export_type} - {self.status}"


class ThreatStatistic(models.Model):
    """Pre-computed threat statistics for performance"""
    date = models.DateField(unique=True)
    total_threats = models.IntegerField(default=0)
    critical_threats = models.IntegerField(default=0)
    warning_threats = models.IntegerField(default=0)
    info_threats = models.IntegerField(default=0)
    arp_spoofs = models.IntegerField(default=0)
    dns_spoofs = models.IntegerField(default=0)
    rogue_dhcp = models.IntegerField(default=0)
    mac_duplicates = models.IntegerField(default=0)
    blocked_ips = models.IntegerField(default=0)
    alerts_sent = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'reports_threat_statistic'
        verbose_name = 'Threat Statistic'
        verbose_name_plural = 'Threat Statistics'
        ordering = ['-date']
        indexes = [
            models.Index(fields=['-date']),
        ]
    
    def __str__(self):
        return f"Stats for {self.date}: {self.total_threats} threats"
