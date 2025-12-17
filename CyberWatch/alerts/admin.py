from django.contrib import admin
from .models import Alert, AlertRule, NotificationChannel, AlertHistory, EmailNotification


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'threat', 'status', 'email_sent', 'acknowledged_by', 'created_at']
    list_filter = ['status', 'email_sent']
    search_fields = ['threat__description', 'notes']
    date_hierarchy = 'created_at'
    raw_id_fields = ['threat']


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'threat_type', 'min_severity', 'is_active', 'send_email', 'auto_block']
    list_filter = ['threat_type', 'min_severity', 'is_active', 'send_email', 'auto_block']
    search_fields = ['name', 'description']


@admin.register(NotificationChannel)
class NotificationChannelAdmin(admin.ModelAdmin):
    list_display = ['name', 'channel_type', 'is_active', 'created_at']
    list_filter = ['channel_type', 'is_active']
    search_fields = ['name']


@admin.register(AlertHistory)
class AlertHistoryAdmin(admin.ModelAdmin):
    list_display = ['alert', 'action', 'performed_by', 'timestamp']
    list_filter = ['action']
    search_fields = ['details']
    date_hierarchy = 'timestamp'
    raw_id_fields = ['alert']


@admin.register(EmailNotification)
class EmailNotificationAdmin(admin.ModelAdmin):
    list_display = ['alert', 'recipient', 'subject', 'success', 'sent_at']
    list_filter = ['success']
    search_fields = ['recipient', 'subject']
    date_hierarchy = 'sent_at'
    raw_id_fields = ['alert']
