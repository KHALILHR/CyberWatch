from django.contrib import admin
from .models import Report, LogEntry, ReportTemplate, ExportJob, ThreatStatistic


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['title', 'report_type', 'format', 'file_size', 'generated_by', 'generated_at']
    list_filter = ['report_type', 'format', 'is_scheduled']
    search_fields = ['title', 'description']
    date_hierarchy = 'generated_at'


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ['level', 'module', 'message_preview', 'created_at']
    list_filter = ['level', 'module']
    search_fields = ['message']
    date_hierarchy = 'created_at'
    
    def message_preview(self, obj):
        return obj.message[:100]
    message_preview.short_description = 'Message'


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ['name', 'template_type', 'is_default', 'is_active', 'created_at']
    list_filter = ['template_type', 'is_default', 'is_active']
    search_fields = ['name', 'description']


@admin.register(ExportJob)
class ExportJobAdmin(admin.ModelAdmin):
    list_display = ['job_id', 'export_type', 'status', 'progress', 'created_by', 'created_at']
    list_filter = ['status', 'export_type']
    search_fields = ['job_id']
    date_hierarchy = 'created_at'


@admin.register(ThreatStatistic)
class ThreatStatisticAdmin(admin.ModelAdmin):
    list_display = ['date', 'total_threats', 'critical_threats', 'blocked_ips', 'alerts_sent']
    list_filter = ['date']
    date_hierarchy = 'date'
