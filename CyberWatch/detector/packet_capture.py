"""
Packet Capture Manager using Scapy
"""
import threading
import logging
from scapy.all import sniff, ARP, DNS, DHCP, IP, Ether
from django.conf import settings
from .models import NetworkInterface
from .arp_detector import ARPDetector
from .dns_detector import DNSDetector
from .dhcp_detector import DHCPDetector

logger = logging.getLogger('detector')


class PacketCaptureManager:
    """Manages packet capture threads for network monitoring"""
    
    def __init__(self):
        self.capture_threads = {}
        self.stop_events = {}
        self.detectors = {}
    
    def start_capture(self, interface):
        """Start packet capture on a network interface"""
        if interface.id in self.capture_threads:
            logger.warning(f"Capture already running on {interface.name}")
            return False
        
        # Initialize detectors
        self.detectors[interface.id] = {
            'arp': ARPDetector(interface),
            'dns': DNSDetector(interface),
            'dhcp': DHCPDetector(interface),
        }
        
        # Create stop event
        stop_event = threading.Event()
        self.stop_events[interface.id] = stop_event
        
        # Start capture thread
        thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, stop_event),
            daemon=True
        )
        thread.start()
        self.capture_threads[interface.id] = thread
        
        logger.info(f"Started packet capture on {interface.name}")
        return True
    
    def stop_capture(self, interface):
        """Stop packet capture on a network interface"""
        if interface.id not in self.capture_threads:
            logger.warning(f"No capture running on {interface.name}")
            return False
        
        # Signal stop
        self.stop_events[interface.id].set()
        
        # Wait for thread to finish
        self.capture_threads[interface.id].join(timeout=5)
        
        # Cleanup
        del self.capture_threads[interface.id]
        del self.stop_events[interface.id]
        del self.detectors[interface.id]
        
        logger.info(f"Stopped packet capture on {interface.name}")
        return True
    
    def _capture_packets(self, interface, stop_event):
        """Capture packets in a loop"""
        try:
            # Capture packets until stop event is set
            sniff(
                iface=interface.name,
                prn=lambda pkt: self._process_packet(pkt, interface),
                stop_filter=lambda _: stop_event.is_set(),
                store=False
            )
        except Exception as e:
            logger.error(f"Error capturing packets on {interface.name}: {e}")
    
    def _process_packet(self, packet, interface):
        """Process each captured packet"""
        try:
            detectors = self.detectors.get(interface.id, {})
            
            # ARP packet detection
            if packet.haslayer(ARP):
                detectors['arp'].analyze_packet(packet)
            
            # DNS packet detection
            if packet.haslayer(DNS):
                detectors['dns'].analyze_packet(packet)
            
            # DHCP packet detection
            if packet.haslayer(DHCP):
                detectors['dhcp'].analyze_packet(packet)
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")


# Singleton instance
_capture_manager = None

def get_capture_manager():
    """Get singleton packet capture manager"""
    global _capture_manager
    if _capture_manager is None:
        _capture_manager = PacketCaptureManager()
    return _capture_manager
