"""
Rogue DHCP Server Detector
"""
import logging
from scapy.all import DHCP, BOOTP, IP, Ether
from django.utils import timezone
from .models import DetectedThreat, DHCPServer
from alerts.alert_manager import AlertManager

logger = logging.getLogger('detector')


class DHCPDetector:
    """Detects rogue DHCP servers"""
    
    def __init__(self, interface):
        self.interface = interface
        self.legitimate_dhcp_servers = set()  # Should be configured
        self.alert_manager = AlertManager()
    
    def analyze_packet(self, packet):
        """Analyze DHCP packet for rogue servers"""
        try:
            if not packet.haslayer(DHCP):
                return
            
            # Check for DHCP Offer or ACK (server responses)
            dhcp_options = packet[DHCP].options
            msg_type = None
            
            for opt in dhcp_options:
                if opt[0] == 'message-type':
                    msg_type = opt[1]
                    break
            
            # DHCP Offer (2) or ACK (5)
            if msg_type in [2, 5]:
                self._check_rogue_dhcp(packet)
        
        except Exception as e:
            logger.error(f"Error analyzing DHCP packet: {e}")
    
    def _check_rogue_dhcp(self, packet):
        """Check for rogue DHCP server"""
        try:
            server_ip = packet[IP].src if packet.haslayer(IP) else None
            server_mac = packet[Ether].src if packet.haslayer(Ether) else None
            
            if not server_ip or not server_mac:
                return
            
            # Check if this server is legitimate
            is_legitimate = server_ip in self.legitimate_dhcp_servers
            
            # Update/create DHCP server record
            dhcp_server, created = DHCPServer.objects.update_or_create(
                server_ip=server_ip,
                server_mac=server_mac,
                interface=self.interface,
                defaults={
                    'is_legitimate': is_legitimate,
                }
            )
            
            dhcp_server.offer_count += 1
            dhcp_server.save()
            
            # If not legitimate, create threat
            if not is_legitimate:
                self._create_threat(
                    threat_type='ROGUE_DHCP',
                    severity='CRITICAL',
                    source_ip=server_ip,
                    source_mac=server_mac,
                    description=f"Rogue DHCP server detected: {server_ip} ({server_mac})",
                    raw_data={
                        'server_ip': server_ip,
                        'server_mac': server_mac,
                        'offer_count': dhcp_server.offer_count,
                    }
                )
        
        except Exception as e:
            logger.error(f"Error checking rogue DHCP: {e}")
    
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
