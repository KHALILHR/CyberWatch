"""
Cross-platform IP Blocking Module
• Windows  → netsh advfirewall
• Linux    → iptables (requires root)
• macOS    → pfctl anchor rule (requires root)
"""
import subprocess
import platform
import logging
import ctypes
from django.utils import timezone
from .models import BlockedIP

logger = logging.getLogger('detector')


class IPBlocker:
    """Blocks/unblocks IP addresses on the current OS"""
    
    def __init__(self):
        self.rule_prefix = "CyberWatch_Block"
        self.os = platform.system().lower()
        self.last_error = None

    def _windows_rule_exists(self, rule_name):
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'],
            capture_output=True,
            text=True,
        )
        combined = (result.stdout or '') + (result.stderr or '')
        if 'No rules match the specified criteria' in combined:
            return False
        return True

    def _is_windows_admin(self):
        if not self.os.startswith('win'):
            return True
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _run_cmd(self, cmd):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            combined = ((result.stdout or '') + '\n' + (result.stderr or '')).strip()
            self.last_error = combined or f'Command failed ({result.returncode})'
            return False
        return True
    
    def block_ip(self, ip_address, reason="Detected threat", threat=None, is_permanent=False):
        """Block an IP address using Windows Firewall"""
        try:
            self.last_error = None

            if self.os.startswith('win') and not self._is_windows_admin():
                self.last_error = 'Administrator privileges required to modify Windows Firewall rules. Run CyberWatch as Administrator.'
                return False

            # Check if already blocked
            existing = BlockedIP.objects.filter(ip_address=ip_address, is_active=True).first()
            if existing:
                if self.os.startswith('win'):
                    in_name = f"{existing.rule_name}_IN"
                    out_name = f"{existing.rule_name}_OUT"
                    if self._windows_rule_exists(in_name) and self._windows_rule_exists(out_name):
                        logger.info(f"IP {ip_address} is already blocked")
                        return True
                else:
                    logger.info(f"IP {ip_address} is already blocked")
                    return True
            
            # Create firewall rule name
            rule_name = f"{self.rule_prefix}_{ip_address.replace('.', '_')}"
            
            if self.os.startswith('win'):
                # Windows: netsh (create both inbound + outbound rules)
                cmd_in = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}_IN',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip_address}',
                    'profile=any',
                ]
                cmd_out = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}_OUT',
                    'dir=out',
                    'action=block',
                    f'remoteip={ip_address}',
                    'profile=any',
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
            
            if self.os.startswith('win'):
                if not self._run_cmd(cmd_in):
                    logger.error(f"Failed to block IP {ip_address}: {self.last_error}")
                    return False
                if not self._run_cmd(cmd_out):
                    logger.error(f"Failed to block IP {ip_address}: {self.last_error}")
                    return False
            else:
                if not self._run_cmd(cmd):
                    logger.error(f"Failed to block IP {ip_address}: {self.last_error}")
                    return False

            if True:
                # Record in database
                BlockedIP.objects.update_or_create(
                    ip_address=ip_address,
                    defaults={
                        'reason': reason,
                        'threat': threat,
                        'rule_name': rule_name,
                        'is_permanent': is_permanent,
                        'is_active': True,
                        'unblocked_at': None,
                    }
                )
                
                logger.info(f"Successfully blocked IP {ip_address}")
                return True
        
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            self.last_error = None

            if self.os.startswith('win') and not self._is_windows_admin():
                self.last_error = 'Administrator privileges required to modify Windows Firewall rules. Run CyberWatch as Administrator.'
                return False
            # Get blocked IP record
            try:
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address, is_active=True)
            except BlockedIP.DoesNotExist:
                logger.warning(f"IP {ip_address} is not blocked")
                return True

            # Build OS-specific command
            if self.os.startswith('win'):
                cmd_in = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={blocked_ip.rule_name}_IN'
                ]
                cmd_out = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={blocked_ip.rule_name}_OUT'
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

            if self.os.startswith('win'):
                if not self._run_cmd(cmd_in):
                    logger.error(f"Failed to unblock IP {ip_address}: {self.last_error}")
                    return False
                if not self._run_cmd(cmd_out):
                    logger.error(f"Failed to unblock IP {ip_address}: {self.last_error}")
                    return False
            else:
                if not self._run_cmd(cmd):
                    logger.error(f"Failed to unblock IP {ip_address}: {self.last_error}")
                    return False

            if True:
                blocked_ip.is_active = False
                blocked_ip.unblocked_at = timezone.now()
                blocked_ip.save()
                logger.info(f"Successfully unblocked IP {ip_address}")
                return True

        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def list_blocked_ips(self):
        """List all currently blocked IPs"""
        return BlockedIP.objects.filter(is_active=True)
    
    def is_blocked(self, ip_address):
        """Check if an IP is currently blocked"""
        return BlockedIP.objects.filter(ip_address=ip_address, is_active=True).exists()
