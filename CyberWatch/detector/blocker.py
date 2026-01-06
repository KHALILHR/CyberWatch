"""
Cross-platform IP Blocking Module
• Windows  → netsh advfirewall
• Linux    → iptables (requires root)
• macOS    → pfctl anchor rule (requires root)
"""
import subprocess
import platform
import logging
from django.utils import timezone
from .models import BlockedIP

logger = logging.getLogger('detector')


class IPBlocker:
    """Blocks/unblocks IP addresses on the current OS"""
    
    def __init__(self):
        self.rule_prefix = "CyberWatch_Block"
        self.os = platform.system().lower()
    
    def block_ip(self, ip_address, reason="Detected threat", threat=None, is_permanent=False):
        """Block an IP address using Windows Firewall"""
        try:
            # Check if already blocked
            if BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists():
                logger.info(f"IP {ip_address} is already blocked")
                return True
            
            # Create firewall rule name
            rule_name = f"{self.rule_prefix}_{ip_address.replace('.', '_')}"
            
            if self.os.startswith('win'):
                # Windows: netsh
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip_address}'
                ]
            elif self.os == 'linux':
                # Linux: iptables -I INPUT -s <ip> -j DROP
                cmd = ['iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP']
            elif self.os == 'darwin':
                # macOS: add rule to pfctl via anchor file
                anchor = f"/etc/pf.anchors/{rule_name}"
                pf_rule = f"block drop from {ip_address} to any\n"
                try:
                    with open(anchor, 'w') as f:
                        f.write(pf_rule)
                    cmd = ['pfctl', '-f', '/etc/pf.conf']  # reload rules
                except PermissionError:
                    logger.error('Permission denied writing pf anchor. Run as root.')
                    return False
            else:
                logger.error(f'Unsupported OS for blocking: {self.os}')
                return False
            
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

            # Build OS-specific command
            if self.os.startswith('win'):
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={blocked_ip.rule_name}'
                ]
            elif self.os == 'linux':
                cmd = ['iptables', '-D', 'INPUT', '-s', blocked_ip.ip_address, '-j', 'DROP']
            elif self.os == 'darwin':
                anchor = f"/etc/pf.anchors/{blocked_ip.rule_name}"
                subprocess.run(['rm', '-f', anchor])
                cmd = ['pfctl', '-f', '/etc/pf.conf']
            else:
                logger.error(f'Unsupported OS for unblocking: {self.os}')
                return False

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
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
        """Unblock an IP address"""
        try:
            # Get blocked IP record
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address, is_active=True)
            except BlockedIP.DoesNotExist:
                logger.warning(f"IP {ip_address} is not blocked")
                return True
            
            # Remove firewall rule
            if self.os.startswith('win'):
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={blocked_ip.rule_name}'
            ]
        elif self.os == 'linux':
            cmd = ['iptables', '-D', 'INPUT', '-s', blocked_ip.ip_address, '-j', 'DROP']
        elif self.os == 'darwin':
            anchor = f"/etc/pf.anchors/{blocked_ip.rule_name}"
            # Remove anchor file then reload pf
            subprocess.run(['rm', '-f', anchor])
            cmd = ['pfctl', '-f', '/etc/pf.conf']
        else:
            logger.error(f'Unsupported OS for unblocking: {self.os}')
            return False
            
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
