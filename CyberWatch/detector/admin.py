from django.contrib import admin
from .models import (
    NetworkInterface, DetectedThreat, ARPEntry,
    DNSQuery, DHCPServer, MACAddress, BlockedIP
)


@admin.register(NetworkInterface)
class NetworkInterfaceAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip_address', 'mac_address', 'is_active', 'is_monitoring']
    list_filter = ['is_active', 'is_monitoring']
    search_fields = ['name', 'ip_address', 'mac_address']


@admin.register(DetectedThreat)
class DetectedThreatAdmin(admin.ModelAdmin):
    list_display = ['threat_type', 'severity', 'source_ip', 'source_mac', 'is_blocked', 'detected_at']
    list_filter = ['threat_type', 'severity', 'is_blocked', 'is_resolved']
    search_fields = ['source_ip', 'source_mac', 'target_ip', 'description']
    date_hierarchy = 'detected_at'


@admin.register(ARPEntry)
class ARPEntryAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'mac_address', 'interface', 'is_legitimate', 'times_changed', 'last_seen']
    list_filter = ['is_legitimate', 'interface']
    search_fields = ['ip_address', 'mac_address']


@admin.register(DNSQuery)
class DNSQueryAdmin(admin.ModelAdmin):
    list_display = ['domain', 'query_type', 'resolved_ip', 'is_legitimate', 'queried_at']
    list_filter = ['query_type', 'is_legitimate']
    search_fields = ['domain', 'resolved_ip']
    date_hierarchy = 'queried_at'


@admin.register(DHCPServer)
class DHCPServerAdmin(admin.ModelAdmin):
    list_display = ['server_ip', 'server_mac', 'is_legitimate', 'offer_count', 'last_seen']
    list_filter = ['is_legitimate']
    search_fields = ['server_ip', 'server_mac']


@admin.register(MACAddress)
class MACAddressAdmin(admin.ModelAdmin):
    list_display = ['mac_address', 'vendor', 'is_whitelisted', 'is_blacklisted', 'last_seen']
    list_filter = ['is_whitelisted', 'is_blacklisted']
    search_fields = ['mac_address', 'vendor']


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'is_permanent', 'is_active', 'blocked_at', 'expires_at']
    list_filter = ['is_permanent', 'is_active']
    search_fields = ['ip_address', 'reason']
    date_hierarchy = 'blocked_at'
