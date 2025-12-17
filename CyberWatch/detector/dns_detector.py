"""
DNS Spoofing Detector
"""
import logging
from scapy.all import DNS, DNSQR, DNSRR, IP
from django.utils import timezone
from .models import DetectedThreat, DNSQuery
from alerts.alert_manager import AlertManager
import socket

logger = logging.getLogger('detector')


class DNSDetector:
    """Detects DNS spoofing attacks"""
    
    def __init__(self, interface):
        self.interface = interface
        self.dns_cache = {}
        self.alert_manager = AlertManager()
    
    def analyze_packet(self, packet):
        """Analyze DNS packet for spoofing"""
        try:
            if not packet.haslayer(DNS):
                return
            
            dns = packet[DNS]
            
            # Only process DNS responses
            if dns.qr == 1:  # Response
                self._check_dns_spoofing(packet, dns)
        
        except Exception as e:
            logger.error(f"Error analyzing DNS packet: {e}")
    
    def _check_dns_spoofing(self, packet, dns):
        """Check for DNS spoofing indicators"""
        try:
            # Extract query and answer
            if not dns.qd or not dns.an:
                return
            
            query_name = dns.qd.qname.decode('utf-8').rstrip('.')
            
            # Get answered IP
            for i in range(dns.ancount):
                answer = dns.an[i]
                if answer.type == 1:  # A record
                    resolved_ip = answer.rdata
                    
                    # Perform legitimate DNS lookup for comparison
                    try:
                        legitimate_ips = socket.gethostbyname_ex(query_name)[2]
                        
                        # Check if resolved IP matches legitimate lookup
                        if resolved_ip not in legitimate_ips:
                            self._create_threat(
                                threat_type='DNS_SPOOF',
                                severity='CRITICAL',
                                source_ip=packet[IP].src if packet.haslayer(IP) else None,
                                description=f"DNS spoofing detected for {query_name}: got {resolved_ip}, expected {legitimate_ips}",
                                raw_data={
                                    'domain': query_name,
                                    'spoofed_ip': resolved_ip,
                                    'legitimate_ips': legitimate_ips,
                                }
                            )
                    except socket.gaierror:
                        # Cannot resolve - might be suspicious
                        pass
                    
                    # Log DNS query
                    DNSQuery.objects.create(
                        domain=query_name,
                        query_type='A',
                        resolved_ip=resolved_ip,
                        interface=self.interface,
                        response_time=0,  # Would need to calculate from request/response timing
                    )
        
        except Exception as e:
            logger.error(f"Error checking DNS spoofing: {e}")
    
    def _create_threat(self, threat_type, severity, source_ip, description, raw_data):
        """Create a detected threat"""
        threat = DetectedThreat.objects.create(
            threat_type=threat_type,
            severity=severity,
            source_ip=source_ip,
            description=description,
            raw_data=raw_data,
            interface=self.interface,
            detected_at=timezone.now()
        )
        
        logger.warning(f"Threat detected: {description}")
        
        # Trigger alert
        self.alert_manager.create_alert(threat)
        
        return threat
