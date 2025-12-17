from django.db import models
from django.utils import timezone
import json


class NetworkInterface(models.Model):
    """Network interfaces available for monitoring"""
    name = models.CharField(max_length=100, unique=True)
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17)
    is_active = models.BooleanField(default=True)
    is_monitoring = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'detector_network_interface'
        verbose_name = 'Network Interface'
        verbose_name_plural = 'Network Interfaces'
        ordering = ['-is_active', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.ip_address})"


class DetectedThreat(models.Model):
    """Main model for all detected threats"""
    THREAT_TYPES = [
        ('ARP_SPOOF', 'ARP Spoofing'),
        ('ARP_POISON', 'ARP Poisoning'),
        ('DNS_SPOOF', 'DNS Spoofing'),
        ('ROGUE_DHCP', 'Rogue DHCP Server'),
        ('MAC_DUPLICATE', 'MAC Address Duplication'),
        ('ARP_SCAN', 'ARP Scan Detected'),
    ]
    
    SEVERITY_LEVELS = [
        ('INFO', 'Informational'),
        ('WARNING', 'Warning'),
        ('CRITICAL', 'Critical'),
    ]
    
    threat_type = models.CharField(max_length=20, choices=THREAT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='WARNING')
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_mac = models.CharField(max_length=17, null=True, blank=True)
    target_ip = models.GenericIPAddressField(null=True, blank=True)
    target_mac = models.CharField(max_length=17, null=True, blank=True)
    description = models.TextField()
    raw_data = models.JSONField(default=dict, blank=True)
    interface = models.ForeignKey(NetworkInterface, on_delete=models.SET_NULL, null=True, blank=True)
    is_blocked = models.BooleanField(default=False)
    is_resolved = models.BooleanField(default=False)
    detected_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'detector_detected_threat'
        verbose_name = 'Detected Threat'
        verbose_name_plural = 'Detected Threats'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['-detected_at']),
            models.Index(fields=['threat_type', '-detected_at']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.get_threat_type_display()} - {self.severity} at {self.detected_at}"
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'threat_type': self.threat_type,
            'threat_type_display': self.get_threat_type_display(),
            'severity': self.severity,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'target_ip': self.target_ip,
            'target_mac': self.target_mac,
            'description': self.description,
            'is_blocked': self.is_blocked,
            'is_resolved': self.is_resolved,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
        }


class ARPEntry(models.Model):
    """ARP table monitoring for suspicious changes"""
    ip_address = models.GenericIPAddressField()
    mac_address = models.CharField(max_length=17)
    interface = models.ForeignKey(NetworkInterface, on_delete=models.CASCADE)
    is_legitimate = models.BooleanField(default=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    times_changed = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'detector_arp_entry'
        verbose_name = 'ARP Entry'
        verbose_name_plural = 'ARP Entries'
        unique_together = ['ip_address', 'interface']
        ordering = ['-last_seen']
    
    def __str__(self):
        return f"{self.ip_address} -> {self.mac_address}"


class DNSQuery(models.Model):
    """DNS query logging and spoofing detection"""
    domain = models.CharField(max_length=255)
    query_type = models.CharField(max_length=10, default='A')  # A, AAAA, MX, etc.
    resolved_ip = models.GenericIPAddressField()
    is_legitimate = models.BooleanField(default=True)
    response_time = models.FloatField(help_text="Response time in milliseconds")
    interface = models.ForeignKey(NetworkInterface, on_delete=models.CASCADE)
    queried_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'detector_dns_query'
        verbose_name = 'DNS Query'
        verbose_name_plural = 'DNS Queries'
        ordering = ['-queried_at']
        indexes = [
            models.Index(fields=['domain', '-queried_at']),
        ]
    
    def __str__(self):
        return f"{self.domain} -> {self.resolved_ip}"


class DHCPServer(models.Model):
    """Detected DHCP servers (legitimate and rogue)"""
    server_ip = models.GenericIPAddressField()
    server_mac = models.CharField(max_length=17)
    is_legitimate = models.BooleanField(default=False)
    interface = models.ForeignKey(NetworkInterface, on_delete=models.CASCADE)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    offer_count = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'detector_dhcp_server'
        verbose_name = 'DHCP Server'
        verbose_name_plural = 'DHCP Servers'
        unique_together = ['server_ip', 'server_mac', 'interface']
        ordering = ['-last_seen']
    
    def __str__(self):
        status = "Legitimate" if self.is_legitimate else "Rogue"
        return f"{status} DHCP Server: {self.server_ip}"


class MACAddress(models.Model):
    """Known MAC addresses and duplication tracking"""
    mac_address = models.CharField(max_length=17, unique=True)
    vendor = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    is_whitelisted = models.BooleanField(default=False)
    is_blacklisted = models.BooleanField(default=False)
    associated_ips = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'detector_mac_address'
        verbose_name = 'MAC Address'
        verbose_name_plural = 'MAC Addresses'
        ordering = ['-last_seen']
    
    def __str__(self):
        return self.mac_address


class BlockedIP(models.Model):
    """Blocked IP addresses with firewall rules"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    threat = models.ForeignKey(DetectedThreat, on_delete=models.SET_NULL, null=True, blank=True)
    rule_name = models.CharField(max_length=255, blank=True)
    is_permanent = models.BooleanField(default=False)
    blocked_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    unblocked_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'detector_blocked_ip'
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        ordering = ['-blocked_at']
    
    def __str__(self):
        return f"Blocked: {self.ip_address}"
