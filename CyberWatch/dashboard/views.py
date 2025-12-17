"""
CyberWatch Dashboard Views
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta

from detector.models import DetectedThreat, NetworkInterface, ARPEntry, DNSQuery, DHCPServer, BlockedIP
from alerts.models import Alert
from reports.models import ThreatStatistic, Report

import json


def index(request):
    """Main dashboard view"""
    from detector.network_discovery import ensure_interfaces_exist
    
    # Auto-discover network interfaces if none exist
    ensure_interfaces_exist()
    
    # Get recent threats
    recent_threats = DetectedThreat.objects.all()[:10]
    
    # Get statistics for today
    today = timezone.now().date()
    total_threats_today = DetectedThreat.objects.filter(detected_at__date=today).count()
    critical_threats_today = DetectedThreat.objects.filter(
        detected_at__date=today,
        severity='CRITICAL'
    ).count()
    
    # Get monitoring status
    active_interfaces = NetworkInterface.objects.filter(is_monitoring=True)
    monitoring_active = active_interfaces.exists()
    
    # Get blocked IPs count
    blocked_ips_count = BlockedIP.objects.filter(is_active=True).count()
    
    # Get all available interfaces for display
    all_interfaces = NetworkInterface.objects.filter(is_active=True)
    
    context = {
        'recent_threats': recent_threats,
        'total_threats_today': total_threats_today,
        'critical_threats_today': critical_threats_today,
        'monitoring_active': monitoring_active,
        'active_interfaces': active_interfaces,
        'all_interfaces': all_interfaces,
        'blocked_ips_count': blocked_ips_count,
    }
    
    return render(request, 'dashboard/index.html', context)


def threats_list(request):
    """List all detected threats"""
    threats = DetectedThreat.objects.all()
    
    # Filtering
    threat_type = request.GET.get('type')
    severity = request.GET.get('severity')
    
    if threat_type:
        threats = threats.filter(threat_type=threat_type)
    if severity:
        threats = threats.filter(severity=severity)
    
    # Order by most recent first
    threats = threats.order_by('-detected_at')[:100]
    
    context = {
        'threats': threats,
        'threat_types': DetectedThreat.THREAT_TYPES,
        'severity_levels': DetectedThreat.SEVERITY_LEVELS,
    }
    
    return render(request, 'dashboard/threats.html', context)


def threat_detail(request, threat_id):
    """Threat detail view"""
    threat = get_object_or_404(DetectedThreat, id=threat_id)
    
    context = {
        'threat': threat,
    }
    
    return render(request, 'dashboard/threat_detail.html', context)


@require_http_methods(["POST"])
def start_monitoring(request):
    """Start network monitoring"""
    from detector.packet_capture import get_capture_manager
    
    interface_id = request.POST.get('interface_id')
    
    # If no interface specified, use the first active one
    if not interface_id:
        interface = NetworkInterface.objects.filter(is_active=True).first()
        if not interface:
            return JsonResponse({
                'status': 'error', 
                'message': 'No network interfaces available. Please add one in the admin panel.'
            }, status=400)
    else:
        interface = get_object_or_404(NetworkInterface, id=interface_id)
    
    # Check if already monitoring
    if interface.is_monitoring:
        return JsonResponse({
            'status': 'info',
            'message': f'Interface {interface.name} is already being monitored'
        })
    
    interface.is_monitoring = True
    interface.save()
    
    # Start capture
    try:
        manager = get_capture_manager()
        manager.start_capture(interface)
        
        return JsonResponse({
            'status': 'success',
            'message': f'Monitoring started on {interface.name}'
        })
    except Exception as e:
        interface.is_monitoring = False
        interface.save()
        return JsonResponse({
            'status': 'error',
            'message': f'Failed to start monitoring: {str(e)}'
        }, status=500)


@require_http_methods(["POST"])
def stop_monitoring(request):
    """Stop network monitoring"""
    from detector.packet_capture import get_capture_manager
    
    interface_id = request.POST.get('interface_id')
    
    # If no interface specified, stop all monitoring interfaces
    if not interface_id:
        interfaces = NetworkInterface.objects.filter(is_monitoring=True)
        if not interfaces.exists():
            return JsonResponse({
                'status': 'info',
                'message': 'No interfaces are currently being monitored'
            })
        
        manager = get_capture_manager()
        stopped_count = 0
        
        for interface in interfaces:
            try:
                manager.stop_capture(interface)
                interface.is_monitoring = False
                interface.save()
                stopped_count += 1
            except Exception as e:
                pass  # Continue stopping others
        
        return JsonResponse({
            'status': 'success',
            'message': f'Monitoring stopped on {stopped_count} interface(s)'
        })
    else:
        interface = get_object_or_404(NetworkInterface, id=interface_id)
        
        interface.is_monitoring = False
        interface.save()
        
        # Stop capture
        try:
            manager = get_capture_manager()
            manager.stop_capture(interface)
            
            return JsonResponse({
                'status': 'success',
                'message': f'Monitoring stopped on {interface.name}'
            })
        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to stop monitoring: {str(e)}'
            }, status=500)


@require_http_methods(["POST"])
def block_ip(request, threat_id):
    """Block an IP address"""
    from detector.blocker import IPBlocker
    
    threat = get_object_or_404(DetectedThreat, id=threat_id)
    
    if threat.source_ip:
        blocker = IPBlocker()
        success = blocker.block_ip(threat.source_ip, threat=threat)
        
        if success:
            threat.is_blocked = True
            threat.save()
            return JsonResponse({'status': 'success', 'message': f'IP {threat.source_ip} blocked'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Failed to block IP'}, status=500)
    
    return JsonResponse(stats)


@require_http_methods(["POST"])
def generate_report(request):
    """Generate a new security report"""
    from reports.models import Report
    from detector.models import DetectedThreat
    import csv
    import json
    import os
    from django.conf import settings
    
    # Get form data
    title = request.POST.get('title')
    report_type = request.POST.get('type')
    file_format = request.POST.get('format')
    description = request.POST.get('description', '')
    
    # Determine date range
    end_date = timezone.now()
    if report_type == 'DAILY':
        start_date = end_date - timedelta(days=1)
    elif report_type == 'WEEKLY':
        start_date = end_date - timedelta(weeks=1)
    elif report_type == 'MONTHLY':
        start_date = end_date - timedelta(days=30)
    else:  # Custom
        start_date = end_date - timedelta(days=7)  # Default to 1 week for custom
    
    # Fetch data
    threats = DetectedThreat.objects.filter(
        detected_at__range=(start_date, end_date)
    ).order_by('-detected_at')
    
    # Create report object
    report = Report(
        title=title,
        report_type=report_type,
        format=file_format,
        description=description,
        start_date=start_date,
        end_date=end_date,
        is_scheduled=False
    )
    
    # Generate file content
    filename = f"report_{report_type}_{end_date.strftime('%Y%m%d_%H%M%S')}.{file_format.lower()}"
    reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    file_path = os.path.join(reports_dir, filename)
    
    try:
        if file_format == 'CSV':
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Type', 'Severity', 'Source IP', 'Detected At', 'Description'])
                for threat in threats:
                    writer.writerow([
                        threat.id,
                        threat.get_threat_type_display(),
                        threat.severity,
                        threat.source_ip,
                        threat.detected_at,
                        threat.description
                    ])
        elif file_format == 'JSON':
            data = []
            for threat in threats:
                data.append({
                    'id': threat.id,
                    'type': threat.threat_type,
                    'severity': threat.severity,
                    'source_ip': threat.source_ip,
                    'detected_at': threat.detected_at.isoformat(),
                    'description': threat.description
                })
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
        
        # Save report with file info
        report.file_path = f"reports/{filename}"
        report.file_size = os.path.getsize(file_path)
        if request.user.is_authenticated:
            report.generated_by = request.user
        report.save()
        
        return redirect('dashboard:reports')
        
    except Exception as e:
        # Handle errors (could add message framework here)
        print(f"Error generating report: {e}")
        return redirect('dashboard:reports')


@require_http_methods(["POST"])
def unblock_ip(request, ip_id):
    """Unblock an IP address"""
    from detector.blocker import IPBlocker
    
    blocked_ip = get_object_or_404(BlockedIP, id=ip_id)
    
    blocker = IPBlocker()
    success = blocker.unblock_ip(blocked_ip.ip_address)
    
    if success:
        blocked_ip.is_active = False
        blocked_ip.unblocked_at = timezone.now()
        blocked_ip.save()
        
        return JsonResponse({'status': 'success', 'message': f'IP {blocked_ip.ip_address} unblocked'})
    else:
        return JsonResponse({'status': 'error', 'message': 'Failed to unblock IP'}, status=500)


def network_status(request):
    """Network status and interface information"""
    interfaces = NetworkInterface.objects.all()
    arp_entries = ARPEntry.objects.all()[:50]
    dhcp_servers = DHCPServer.objects.all()
    
    context = {
        'interfaces': interfaces,
        'arp_entries': arp_entries,
        'dhcp_servers': dhcp_servers,
    }
    
    return render(request, 'dashboard/network_status.html', context)


def reports_view(request):
    """Reports page"""
    reports = Report.objects.all()[:20]
    
    context = {
        'reports': reports,
    }
    
    return render(request, 'dashboard/reports.html', context)


def settings_view(request):
    """Settings page"""
    from alerts.models import AlertRule, NotificationChannel
    
    alert_rules = AlertRule.objects.all()
    notification_channels = NotificationChannel.objects.all()
    
    context = {
        'alert_rules': alert_rules,
        'notification_channels': notification_channels,
    }
    
    return render(request, 'dashboard/settings.html', context)


# API Endpoints for AJAX/WebSocket updates

def api_threats_recent(request):
    """API endpoint for recent threats"""
    recent_threats = DetectedThreat.objects.all()[:10]
    data = [threat.to_dict() for threat in recent_threats]
    return JsonResponse({'threats': data})


def api_statistics(request):
    """API endpoint for statistics"""
    today = timezone.now().date()
    
    stats = {
        'total_threats_today': DetectedThreat.objects.filter(detected_at__date=today).count(),
        'critical_threats_today': DetectedThreat.objects.filter(detected_at__date=today, severity='CRITICAL').count(),
        'blocked_ips': BlockedIP.objects.filter(is_active=True).count(),
        'active_alerts': Alert.objects.filter(status='NEW').count(),
    }
    
    return JsonResponse(stats)
