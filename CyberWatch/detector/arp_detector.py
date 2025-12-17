"""
ARP Spoofing/Poisoning Detector
"""
import logging
from scapy.all import ARP, Ether
from django.utils import timezone
from .models import DetectedThreat, ARPEntry
from alerts.alert_manager import AlertManager

logger = logging.getLogger('detector')


class ARPDetector:
    """Detects ARP spoofing and poisoning attacks"""
    
    def __init__(self, interface):
        self.interface = interface
        self.arp_table = {}
        self.alert_manager = AlertManager()
    
    def analyze_packet(self, packet):
        """Analyze ARP packet for spoofing"""
        try:
            if not packet.haslayer(ARP):
                return
            
            arp = packet[ARP]
            
            # Only process ARP replies
            if arp.op == 2:  # is-at (reply)
                self._check_arp_spoofing(arp)
                self._update_arp_table(arp)
        
        except Exception as e:
            logger.error(f"Error analyzing ARP packet: {e}")
    
    def _check_arp_spoofing(self, arp):
        """Check for ARP spoofing indicators"""
        ip = arp.psrc
        mac = arp.hwsrc
        
        # Check if we've seen this IP before
        if ip in self.arp_table:
            previous_mac = self.arp_table[ip]
            
            # MAC address changed for this IP - potential spoofing
            if previous_mac != mac:
                self._create_threat(
                    threat_type='ARP_SPOOF',
                    severity='CRITICAL',
                    source_ip=ip,
                    source_mac=mac,
                    description=f"ARP spoofing detected: IP {ip} changed from MAC {previous_mac} to {mac}",
                    raw_data={
                        'previous_mac': previous_mac,
                        'new_mac': mac,
                        'ip_address': ip,
                    }
                )
                
                # Update ARP entry in database
                try:
                    entry = ARPEntry.objects.get(ip_address=ip, interface=self.interface)
                    entry.times_changed += 1
                    entry.mac_address = mac
                    entry.is_legitimate = False
                    entry.save()
                except ARPEntry.DoesNotExist:
                    pass
    
    def _update_arp_table(self, arp):
        """Update internal ARP table"""
        ip = arp.psrc
        mac = arp.hwsrc
        
        self.arp_table[ip] = mac
        
        # Update database
        ARPEntry.objects.update_or_create(
            ip_address=ip,
            interface=self.interface,
            defaults={
                'mac_address': mac,
            }
        )
    
    def _create_threat(self, threat_type, severity, source_ip, source_mac, description, raw_data):
        """Create a detected threat"""
        threat = DetectedThreat.objects.create(
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            source_mac=source_mac,
            description=description,
            raw_data=raw_data,
            interface=self.interface,
            detected_at=timezone.now()
        )
        
        logger.warning(f"Threat detected: {description}")
        
        # Trigger alert
        self.alert_manager.create_alert(threat)
        
        return threat
