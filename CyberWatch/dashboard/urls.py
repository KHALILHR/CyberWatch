"""
Dashboard URL Configuration
"""
from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index, name='index'),
    path('threats/', views.threats_list, name='threats_list'),
    path('threats/<int:threat_id>/', views.threat_detail, name='threat_detail'),
    path('network/', views.network_status, name='network_status'),
    path('reports/', views.reports_view, name='reports'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('settings/', views.settings_view, name='settings'),
    
    # Actions
    path('monitoring/start/', views.start_monitoring, name='start_monitoring'),
    path('monitoring/stop/', views.stop_monitoring, name='stop_monitoring'),
    path('threats/<int:threat_id>/block/', views.block_ip, name='block_ip'),
    path('blocked/<int:ip_id>/unblock/', views.unblock_ip, name='unblock_ip'),
    
    # API endpoints
    path('api/threats/recent/', views.api_threats_recent, name='api_threats_recent'),
    path('api/statistics/', views.api_statistics, name='api_statistics'),
    path('api/notification-email/', views.set_notification_email, name='set_notification_email'),
]
