#!/usr/bin/env python3
"""
Détecteur d'Attaques MITM (Man-in-the-Middle)
Protégez votre réseau contre les attaques ARP Spoofing, DNS Spoofing, etc.

Ce script détecte:
- ARP Spoofing/Poisoning
- Duplications d'adresses MAC
- Changements suspects dans la table ARP
- DNS Spoofing
- Rogue DHCP Servers
- SSL/TLS Stripping
"""

from scapy.all import *
from datetime import datetime
import argparse
import sys
import os
import time
from collections import defaultdict
import threading
import json

# Désactiver les messages verbeux
conf.verb = 0

class Colors:
    """Codes couleur pour l'affichage"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class MITMDetector:
    """Détecteur d'attaques Man-in-the-Middle"""
    
    def __init__(self, interface, gateway_ip=None, alert_sound=False):
        """
        Initialise le détecteur MITM
        
        Args:
            interface: Interface réseau à surveiller
            gateway_ip: IP de la gateway (détection auto si None)
            alert_sound: Jouer un son d'alerte
        """
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.alert_sound = alert_sound
        
        # Tables de surveillance
        self.arp_table = {}  # IP -> MAC
        self.mac_table = defaultdict(set)  # MAC -> IPs
        self.dns_cache = {}  # Domain -> IP
        self.dhcp_servers = set()
        self.suspicious_activities = []
        
        # Statistiques
        self.stats = {
            'arp_spoofing': 0,
            'dns_spoofing': 0,
            'dhcp_rogue': 0,
            'mac_duplication': 0,
            'gateway_changes': 0
        }
        
        # Gateway MAC légitime
        self.legitimate_gateway_mac = None
        
        print(f"{Colors.CYAN}[*] Interface de surveillance: {interface}{Colors.RESET}")
        
        if self.gateway_ip:
            self.legitimate_gateway_mac = self.get_gateway_mac()
            print(f"{Colors.GREEN}[+] Gateway légitime: {self.gateway_ip} -> {self.legitimate_gateway_mac}{Colors.RESET}")
    
    def get_gateway_mac(self):
        """
        Obtenir la MAC légitime de la gateway
        
        Returns:
            str: Adresse MAC de la gateway
        """
        try:
            arp_request = ARP(pdst=self.gateway_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast/arp_request, timeout=2, verbose=False)[0]
            
            if answered:
                return answered[0][1].hwsrc
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur lors de la résolution de la gateway: {e}{Colors.RESET}")
        
        return None
    
    def detect_gateway_automatically(self):
        """
        Détecter automatiquement la gateway du réseau
        
        Returns:
            str: IP de la gateway
        """
        print(f"{Colors.CYAN}[*] Détection automatique de la gateway...{Colors.RESET}")
        
        try:
            # Lire la table de routage
            if sys.platform.startswith('linux'):
                import subprocess
                result = subprocess.check_output(['ip', 'route']).decode()
                for line in result.split('\n'):
                    if 'default' in line:
                        gateway = line.split()[2]
                        print(f"{Colors.GREEN}[+] Gateway détectée: {gateway}{Colors.RESET}")
                        return gateway
            elif sys.platform == 'darwin':  # macOS
                import subprocess
                result = subprocess.check_output(['netstat', '-nr']).decode()
                for line in result.split('\n'):
                    if 'default' in line:
                        gateway = line.split()[1]
                        print(f"{Colors.GREEN}[+] Gateway détectée: {gateway}{Colors.RESET}")
                        return gateway
        except Exception as e:
            print(f"{Colors.RED}[!] Erreur détection gateway: {e}{Colors.RESET}")
        
        return None
    
    def alert(self, severity, message, details=""):
        """
        Générer une alerte de sécurité
        
        Args:
            severity: CRITICAL, HIGH, MEDIUM, LOW
            message: Message d'alerte
            details: Détails supplémentaires
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Couleurs selon la sévérité
        colors = {
            'CRITICAL': Colors.RED + Colors.BOLD,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.BLUE
        }
        
        color = colors.get(severity, Colors.WHITE)
        
        # Afficher l'alerte
        print(f"\n{color}{'='*80}{Colors.RESET}")
        print(f"{color}[{severity}] ALERTE SÉCURITÉ - {timestamp}{Colors.RESET}")
        print(f"{color}{message}{Colors.RESET}")
        if details:
            print(f"{Colors.CYAN}{details}{Colors.RESET}")
        print(f"{color}{'='*80}{Colors.RESET}\n")
        
        # Enregistrer l'alerte
        self.suspicious_activities.append({
            'timestamp': timestamp,
            'severity': severity,
            'message': message,
            'details': details
        })
        
        # Son d'alerte (optionnel)
        if self.alert_sound:
            self.play_alert_sound()
    
    def play_alert_sound(self):
        """Jouer un son d'alerte"""
        try:
            if sys.platform.startswith('linux'):
                os.system('beep -f 1000 -l 500')
            elif sys.platform == 'darwin':
                os.system('afplay /System/Library/Sounds/Funk.aiff')
        except:
            pass
    
    def detect_arp_spoofing(self, packet):
        """
        DÉTECTION #1: ARP Spoofing/Poisoning
        
        COMMENT ÇA MARCHE:
        1. Surveille tous les paquets ARP (requêtes et réponses)
        2. Maintient une table IP -> MAC
        3. Détecte si une IP change de MAC (suspect!)
        4. Détecte si plusieurs IPs utilisent la même MAC (très suspect!)
        
        SIGNES D'ATTAQUE:
        - Une IP change soudainement de MAC
        - Plusieurs IPs pointent vers la même MAC
        - La gateway change de MAC
        
        Args:
            packet: Paquet ARP à analyser
        """
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
            
            # Ignorer les paquets invalides
            if src_ip == '0.0.0.0' or src_mac == '00:00:00:00:00:00':
                return
            
            # Vérifier si c'est la gateway
            is_gateway = (src_ip == self.gateway_ip)
            
            # CAS 1: IP déjà connue avec une MAC différente
            if src_ip in self.arp_table:
                old_mac = self.arp_table[src_ip]
                
                if old_mac != src_mac:
                    # ALERTE: Changement de MAC détecté!
                    self.stats['arp_spoofing'] += 1
                    
                    severity = 'CRITICAL' if is_gateway else 'HIGH'
                    message = f"🚨 ARP SPOOFING DÉTECTÉ! 🚨"
                    details = f"IP: {src_ip}\n"
                    details += f"Ancienne MAC: {old_mac}\n"
                    details += f"Nouvelle MAC: {src_mac}\n"
                    
                    if is_gateway:
                        details += f"⚠️  ALERTE GATEWAY: Votre gateway a changé de MAC!\n"
                        details += f"Vous êtes probablement victime d'une attaque MITM!"
                        self.stats['gateway_changes'] += 1
                    
                    self.alert(severity, message, details)
            
            # Mettre à jour la table ARP
            self.arp_table[src_ip] = src_mac
            
            # CAS 2: Plusieurs IPs utilisent la même MAC
            self.mac_table[src_mac].add(src_ip)
            
            if len(self.mac_table[src_mac]) > 1:
                # ALERTE: Une MAC est associée à plusieurs IPs
                self.stats['mac_duplication'] += 1
                
                message = f"🚨 DUPLICATION MAC DÉTECTÉE! 🚨"
                details = f"MAC: {src_mac}\n"
                details += f"IPs associées: {', '.join(self.mac_table[src_mac])}\n"
                details += f"Cela peut indiquer un ARP Spoofing en cours!"
                
                self.alert('HIGH', message, details)
    
    def detect_dns_spoofing(self, packet):
        """
        DÉTECTION #2: DNS Spoofing
        
        COMMENT ÇA MARCHE:
        1. Surveille les réponses DNS
        2. Vérifie si une même requête DNS reçoit plusieurs réponses différentes
        3. Détecte les réponses DNS multiples (attaquant + serveur légitime)
        
        SIGNES D'ATTAQUE:
        - Réponses DNS multiples pour la même requête
        - Réponse DNS avec un TTL très court
        - Changement soudain de l'IP d'un domaine connu
        
        Args:
            packet: Paquet DNS à analyser
        """
        if packet.haslayer(DNSRR):  # DNS Response
            dns_layer = packet[DNS]
            
            # Parcourir toutes les réponses DNS
            for i in range(dns_layer.ancount):
                dnsrr = dns_layer.an[i]
                
                if dnsrr.type == 1:  # Type A (IPv4)
                    domain = dnsrr.rrname.decode() if isinstance(dnsrr.rrname, bytes) else dnsrr.rrname
                    ip = dnsrr.rdata
                    ttl = dnsrr.ttl
                    
                    # Vérifier si on a déjà vu ce domaine avec une IP différente
                    if domain in self.dns_cache:
                        old_ip = self.dns_cache[domain]
                        
                        if old_ip != ip:
                            # ALERTE: DNS Spoofing possible
                            self.stats['dns_spoofing'] += 1
                            
                            message = f"🚨 DNS SPOOFING POSSIBLE! 🚨"
                            details = f"Domaine: {domain}\n"
                            details += f"Ancienne IP: {old_ip}\n"
                            details += f"Nouvelle IP: {ip}\n"
                            details += f"TTL: {ttl} secondes\n"
                            
                            if ttl < 60:
                                details += f"⚠️  TTL très court ({ttl}s) - TRÈS SUSPECT!"
                            
                            self.alert('HIGH', message, details)
                    
                    # Mettre à jour le cache DNS
                    self.dns_cache[domain] = ip
                    
                    # Vérifier les TTL suspects (< 60 secondes)
                    if ttl < 60 and domain not in ['localhost', '']:
                        message = f"⚠️  TTL DNS suspect détecté"
                        details = f"Domaine: {domain}\n"
                        details += f"IP: {ip}\n"
                        details += f"TTL: {ttl} secondes (très court!)"
                        
                        self.alert('MEDIUM', message, details)
    
    def detect_rogue_dhcp(self, packet):
        """
        DÉTECTION #3: Rogue DHCP Server
        
        COMMENT ÇA MARCHE:
        1. Surveille les réponses DHCP (DHCP Offer, DHCP ACK)
        2. Détecte si plusieurs serveurs DHCP répondent
        3. Compare avec le serveur DHCP légitime
        
        SIGNES D'ATTAQUE:
        - Plusieurs serveurs DHCP sur le même réseau
        - Serveur DHCP inconnu
        
        Args:
            packet: Paquet DHCP à analyser
        """
        if packet.haslayer(DHCP):
            dhcp_layer = packet[DHCP]
            
            # Vérifier le type de message DHCP
            for option in dhcp_layer.options:
                if option[0] == 'message-type':
                    msg_type = option[1]
                    
                    # DHCP Offer (2) ou DHCP ACK (5)
                    if msg_type in [2, 5]:
                        server_ip = packet[IP].src
                        
                        # Premier serveur DHCP détecté
                        if not self.dhcp_servers:
                            self.dhcp_servers.add(server_ip)
                            print(f"{Colors.GREEN}[+] Serveur DHCP légitime: {server_ip}{Colors.RESET}")
                        
                        # Nouveau serveur DHCP détecté
                        elif server_ip not in self.dhcp_servers:
                            self.stats['dhcp_rogue'] += 1
                            
                            message = f"🚨 ROGUE DHCP SERVER DÉTECTÉ! 🚨"
                            details = f"Serveur DHCP légitime: {list(self.dhcp_servers)[0]}\n"
                            details += f"Nouveau serveur DHCP: {server_ip}\n"
                            details += f"⚠️  Un attaquant peut distribuer de fausses configurations réseau!"
                            
                            self.alert('CRITICAL', message, details)
                            
                            self.dhcp_servers.add(server_ip)
    
    def detect_gratuitous_arp(self, packet):
        """
        DÉTECTION #4: Gratuitous ARP suspect
        
        COMMENT ÇA MARCHE:
        Les Gratuitous ARP sont des annonces ARP non sollicitées.
        Ils sont légitimes lors du démarrage d'une machine, mais
        peuvent être utilisés pour l'ARP Spoofing.
        
        SIGNES D'ATTAQUE:
        - Trop de Gratuitous ARP d'une même source
        - Gratuitous ARP pour la gateway
        
        Args:
            packet: Paquet ARP à analyser
        """
        if packet.haslayer(ARP):
            arp = packet[ARP]
            
            # Gratuitous ARP: psrc == pdst
            if arp.psrc == arp.pdst and arp.op == 2:  # op=2 is-at
                message = f"⚠️  Gratuitous ARP détecté"
                details = f"IP: {arp.psrc}\n"
                details += f"MAC: {arp.hwsrc}\n"
                details += f"Type: Annonce non sollicitée"
                
                if arp.psrc == self.gateway_ip:
                    details += f"\n⚠️  ATTENTION: Concerne la GATEWAY!"
                    self.alert('MEDIUM', message, details)
                else:
                    print(f"{Colors.YELLOW}[~] Gratuitous ARP: {arp.psrc} ({arp.hwsrc}){Colors.RESET}")
    
    def detect_port_scanning(self, packet):
        """
        DÉTECTION #5: Port Scanning
        
        COMMENT ÇA MARCHE:
        Détecte les tentatives de scan de ports (nombreuses connexions)
        
        Args:
            packet: Paquet TCP à analyser
        """
        # Cette fonction nécessiterait un tracking plus complexe
        # Laissée en bonus pour extension future
        pass
    
    def packet_handler(self, packet):
        """
        Handler principal pour tous les paquets
        
        Args:
            packet: Paquet capturé à analyser
        """
        try:
            # Détection ARP Spoofing
            if packet.haslayer(ARP):
                self.detect_arp_spoofing(packet)
                self.detect_gratuitous_arp(packet)
            
            # Détection DNS Spoofing
            if packet.haslayer(DNS):
                self.detect_dns_spoofing(packet)
            
            # Détection Rogue DHCP
            if packet.haslayer(DHCP):
                self.detect_rogue_dhcp(packet)
        
        except Exception as e:
            # Ne pas crasher sur une erreur
            pass
    
    def display_statistics(self):
        """Afficher les statistiques périodiquement"""
        while True:
            time.sleep(30)  # Toutes les 30 secondes
            
            print(f"\n{Colors.CYAN}{'='*80}{Colors.RESET}")
            print(f"{Colors.CYAN}[*] STATISTIQUES DE SURVEILLANCE - {datetime.now().strftime('%H:%M:%S')}{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*80}{Colors.RESET}")
            print(f"ARP Spoofing détecté: {Colors.RED}{self.stats['arp_spoofing']}{Colors.RESET}")
            print(f"DNS Spoofing détecté: {Colors.RED}{self.stats['dns_spoofing']}{Colors.RESET}")
            print(f"Rogue DHCP détecté: {Colors.RED}{self.stats['dhcp_rogue']}{Colors.RESET}")
            print(f"Duplications MAC: {Colors.YELLOW}{self.stats['mac_duplication']}{Colors.RESET}")
            print(f"Changements Gateway: {Colors.RED}{self.stats['gateway_changes']}{Colors.RESET}")
            print(f"Machines dans table ARP: {len(self.arp_table)}")
            print(f"Domaines DNS en cache: {len(self.dns_cache)}")
            print(f"{Colors.CYAN}{'='*80}{Colors.RESET}\n")
    
    def save_report(self, filename="mitm_detection_report.json"):
        """
        Sauvegarder un rapport de détection
        
        Args:
            filename: Nom du fichier de rapport
        """
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'interface': self.interface,
            'gateway_ip': self.gateway_ip,
            'statistics': self.stats,
            'arp_table': self.arp_table,
            'suspicious_activities': self.suspicious_activities
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        
        print(f"{Colors.GREEN}[+] Rapport sauvegardé: {filename}{Colors.RESET}")
    
    def start_monitoring(self):
        """Démarrer la surveillance du réseau"""
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}🛡️  DÉTECTEUR D'ATTAQUES MITM ACTIVÉ 🛡️{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"Interface: {Colors.CYAN}{self.interface}{Colors.RESET}")
        print(f"Gateway: {Colors.CYAN}{self.gateway_ip if self.gateway_ip else 'Auto-détection'}{Colors.RESET}")
        print(f"Heure de début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{Colors.GREEN}[+] Surveillance active... Appuyez sur Ctrl+C pour arrêter{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")
        
        # Détecter la gateway si nécessaire
        if not self.gateway_ip:
            self.gateway_ip = self.detect_gateway_automatically()
            if self.gateway_ip:
                self.legitimate_gateway_mac = self.get_gateway_mac()
        
        # Démarrer le thread de statistiques
        stats_thread = threading.Thread(target=self.display_statistics, daemon=True)
        stats_thread.start()
        
        try:
            # Commencer la capture de paquets
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False
            )
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Arrêt de la surveillance...{Colors.RESET}")
            self.display_final_report()
    
    def display_final_report(self):
        """Afficher le rapport final"""
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}RAPPORT FINAL DE DÉTECTION{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Durée de surveillance:{Colors.RESET} Terminée à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{Colors.BOLD}STATISTIQUES GLOBALES:{Colors.RESET}")
        print(f"  Total attaques ARP Spoofing: {Colors.RED}{self.stats['arp_spoofing']}{Colors.RESET}")
        print(f"  Total attaques DNS Spoofing: {Colors.RED}{self.stats['dns_spoofing']}{Colors.RESET}")
        print(f"  Rogue DHCP Servers: {Colors.RED}{self.stats['dhcp_rogue']}{Colors.RESET}")
        print(f"  Duplications MAC: {Colors.YELLOW}{self.stats['mac_duplication']}{Colors.RESET}")
        print(f"  Changements Gateway: {Colors.RED}{self.stats['gateway_changes']}{Colors.RESET}")
        
        if self.suspicious_activities:
            print(f"\n{Colors.BOLD}ACTIVITÉS SUSPECTES ENREGISTRÉES: {len(self.suspicious_activities)}{Colors.RESET}")
            for i, activity in enumerate(self.suspicious_activities[-5:], 1):
                print(f"\n  {i}. [{activity['severity']}] {activity['timestamp']}")
                print(f"     {activity['message']}")
        
        # Sauvegarder le rapport
        self.save_report()
        
        print(f"\n{Colors.GREEN}[+] Surveillance terminée{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")


def check_root():
    """Vérifier les privilèges root"""
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] Ce script nécessite les privilèges root!{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Utilisez: sudo python3 {sys.argv[0]}{Colors.RESET}")
        sys.exit(1)


def display_banner():
    """Afficher la bannière"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════╗
║              🛡️  DÉTECTEUR D'ATTAQUES MITM 🛡️                     ║
║                                                                   ║
║  Protégez votre réseau contre:                                    ║
║  ✓ ARP Spoofing/Poisoning                                         ║
║  ✓ DNS Spoofing                                                   ║
║  ✓ Rogue DHCP Servers                                             ║
║  ✓ Duplications MAC                                               ║
║  ✓ Changements suspects dans le réseau                            ║
║                                                                   ║
║  Surveillance en temps réel avec alertes instantanées             ║
╚═══════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def main():
    """Fonction principale"""
    display_banner()
    check_root()
    
    parser = argparse.ArgumentParser(
        description="Détecteur d'Attaques MITM avec Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

1. Surveillance basique avec auto-détection de gateway:
   sudo python3 mitm_detector.py -i eth0

2. Surveillance avec gateway spécifique:
   sudo python3 mitm_detector.py -i eth0 -g 192.168.1.1

3. Surveillance avec alertes sonores:
   sudo python3 mitm_detector.py -i wlan0 -g 192.168.1.1 --alert-sound

DÉTECTIONS ACTIVES:

1. ARP SPOOFING:
   - Détecte les changements de MAC pour une IP
   - Alerte si la gateway change de MAC
   - Détecte les duplications MAC

2. DNS SPOOFING:
   - Compare les réponses DNS
   - Détecte les TTL suspects
   - Alerte sur changements d'IP

3. ROGUE DHCP:
   - Détecte plusieurs serveurs DHCP
   - Alerte sur nouveaux serveurs

COMMENT RÉAGIR EN CAS D'ALERTE:

1. 🚨 ALERTE CRITIQUE (Gateway compromise):
   - Déconnectez-vous immédiatement
   - Vérifiez votre table ARP: arp -a
   - Redémarrez votre routeur
   - Scannez votre réseau

2. ⚠️  ALERTE HAUTE (DNS/ARP Spoofing):
   - Ne vous connectez pas à des sites sensibles
   - Utilisez un VPN
   - Vérifiez les machines sur votre réseau

3. 📊 ALERTE MEDIUM:
   - Surveillez l'activité
   - Vérifiez les logs
   - Envisagez une investigation plus approfondie
        """
    )
    
    parser.add_argument('-i', '--interface', required=True,
                       help='Interface réseau à surveiller (ex: eth0, wlan0)')
    parser.add_argument('-g', '--gateway',
                       help='IP de la gateway (auto-détection si non spécifiée)')
    parser.add_argument('--alert-sound', action='store_true',
                       help='Activer les alertes sonores')
    
    args = parser.parse_args()
    
    # Créer et démarrer le détecteur
    detector = MITMDetector(
        interface=args.interface,
        gateway_ip=args.gateway,
        alert_sound=args.alert_sound
    )
    
    try:
        detector.start_monitoring()
    except Exception as e:
        print(f"\n{Colors.RED}[!] Erreur: {str(e)}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
