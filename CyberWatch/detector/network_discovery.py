"""
Auto-discover and configure network interfaces
"""
import logging
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
from .models import NetworkInterface

logger = logging.getLogger('detector')


def discover_network_interfaces():
    """
    Automatically discover all network interfaces on this computer
    and add them to the database
    """
    discovered_count = 0
    
    try:
        # Get all network interface names
        interface_names = get_if_list()
        
        for iface_name in interface_names:
            try:
                # Skip loopback and virtual interfaces
                if 'loopback' in iface_name.lower() or 'lo' == iface_name.lower():
                    continue
                
                # Get IP address
                try:
                    ip_addr = get_if_addr(iface_name)
                    if not ip_addr or ip_addr == '0.0.0.0':
                        continue
                except:
                    continue
                
                # Get MAC address
                try:
                    mac_addr = get_if_hwaddr(iface_name)
                    if not mac_addr or mac_addr == '00:00:00:00:00:00':
                        continue
                except:
                    continue
                
                # Create or update interface in database
                interface, created = NetworkInterface.objects.update_or_create(
                    name=iface_name,
                    defaults={
                        'ip_address': ip_addr,
                        'mac_address': mac_addr,
                        'is_active': True,
                    }
                )
                
                if created:
                    discovered_count += 1
                    logger.info(f"Discovered network interface: {iface_name} ({ip_addr})")
                else:
                    logger.info(f"Updated network interface: {iface_name} ({ip_addr})")
            
            except Exception as e:
                logger.warning(f"Could not process interface {iface_name}: {e}")
                continue
        
        logger.info(f"Network discovery complete. Found {discovered_count} new interfaces.")
        return discovered_count
    
    except Exception as e:
        logger.error(f"Error during network interface discovery: {e}")
        return 0


def ensure_interfaces_exist():
    """
    Ensure at least one network interface exists in the database.
    Auto-discover if none exist.
    """
    if not NetworkInterface.objects.exists():
        logger.info("No network interfaces configured. Running auto-discovery...")
        return discover_network_interfaces()
    return 0
