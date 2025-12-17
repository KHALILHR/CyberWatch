"""
IP Blocking Module using Windows Firewall
"""
import subprocess
import logging
from django.utils import timezone
from .models import BlockedIP

logger = logging.getLogger('detector')


class IPBlocker:
    """Blocks/unblocks IP addresses using Windows Firewall"""
    
    def __init__(self):
        self.rule_prefix = "CyberWatch_Block"
    
    def block_ip(self, ip_address, reason="Detected threat", threat=None, is_permanent=False):
        """Block an IP address using Windows Firewall"""
        try:
            # Check if already blocked
            if BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
                logger.info(f"IP {ip_address} is already blocked")
                return True
            
            # Create firewall rule name
            rule_name = f"{self.rule_prefix}_{ip_address.replace('.', '_')}"
            
            # Create Windows Firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Record in database
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    reason=reason,
                    threat=threat,
                    rule_name=rule_name,
                    is_permanent=is_permanent,
                    is_active=True,
                )
                
                logger.info(f"Successfully blocked IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to block IP {ip_address}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            # Get blocked IP record
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address, is_active=True)
            except BlockedIP.DoesNotExist:
                logger.warning(f"IP {ip_address} is not blocked")
                return True
            
            # Remove firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={blocked_ip.rule_name}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Update database
                blocked_ip.is_active = False
                blocked_ip.unblocked_at = timezone.now()
                blocked_ip.save()
                
                logger.info(f"Successfully unblocked IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to unblock IP {ip_address}: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def list_blocked_ips(self):
        """List all currently blocked IPs"""
        return BlockedIP.objects.filter(is_active=True)
    
    def is_blocked(self, ip_address):
        """Check if an IP is currently blocked"""
        return BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists()
