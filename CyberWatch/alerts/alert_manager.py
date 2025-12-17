"""
Alert Manager for creating and managing alerts
"""
import logging
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .models import Alert, AlertRule, EmailNotification

logger = logging.getLogger('alerts')


class AlertManager:
    """Manages alert creation, notifications, and lifecycle"""
    
    def create_alert(self, threat):
        """Create an alert for a detected threat"""
        try:
            # Check for deduplication
            recent_alerts = Alert.objects.filter(
                threat__threat_type=threat.threat_type,
                threat__source_ip=threat.source_ip,
                created_at__gte=timezone.now() - timezone.timedelta(
                    seconds=settings.ALERT_DEDUPLICATION_WINDOW
                )
            )
            
            if recent_alerts.exists():
                logger.info(f"Alert deduplicated for {threat}")
                return None
            
            # Create alert
            alert = Alert.objects.create(
                threat=threat,
                status='NEW',
            )
            
            logger.info(f"Created alert #{alert.id} for threat #{threat.id}")
            
            # Send notifications
            self._send_notifications(alert)
            
            # Auto-block if configured
            self._check_auto_block(alert)
            
            return alert
        
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def _send_notifications(self, alert):
        """Send email notifications for alert"""
        try:
            if not settings.ALERT_EMAIL_RECIPIENTS or not settings.EMAIL_HOST_USER:
                return
            
            threat = alert.threat
            
            # Prepare email
            subject = f"[CyberWatch] {threat.get_severity_display()} Alert: {threat.get_threat_type_display()}"
            
            message = f"""
CyberWatch Security Alert

Severity: {threat.get_severity_display()}
Threat Type: {threat.get_threat_type_display()}
Source IP: {threat.source_ip or 'N/A'}
Source MAC: {threat.source_mac or 'N/A'}
Detected At: {threat.detected_at}

Description:
{threat.description}

View details: http://localhost:8000/threats/{threat.id}/

---
This is an automated alert from CyberWatch MITM Detection System.
"""
            
            # Send email to configured recipients
            recipients = [r for r in settings.ALERT_EMAIL_RECIPIENTS if r]
            
            if recipients:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=recipients,
                    fail_silently=True,
                )
                
                # Record email notification
                for recipient in recipients:
                    EmailNotification.objects.create(
                        alert=alert,
                        recipient=recipient,
                        subject=subject,
                        body=message,
                        success=True,
                    )
                
                # Update alert
                alert.email_sent = True
                alert.email_sent_at = timezone.now()
                alert.save()
                
                logger.info(f"Sent email notifications for alert #{alert.id}")
        
        except Exception as e:
            logger.error(f"Error sending notifications: {e}")
    
    def _check_auto_block(self, alert):
        """Check if IP should be auto-blocked"""
        try:
            if not settings.AUTO_BLOCK_CRITICAL_THREATS:
                return
            
            threat = alert.threat
            
            # Auto-block critical threats
            if threat.severity == 'CRITICAL' and threat.source_ip:
                from detector.blocker import IPBlocker
                
                blocker = IPBlocker()
                if blocker.block_ip(threat.source_ip, threat=threat):
                    threat.is_blocked = True
                    threat.save()
                    logger.info(f"Auto-blocked IP {threat.source_ip} for critical threat")
        
        except Exception as e:
            logger.error(f"Error in auto-block: {e}")
