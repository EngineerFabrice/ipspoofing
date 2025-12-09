"""
===============================================================================
 REAL‑TIME IP SPOOFING SIMULATION + DETECTION DEMONSTRATION
 Author : Fabrice Ndayisaba
 Course : Network Security / Ethical Cybersecurity Research
 Purpose: To demonstrate how spoofed packets look and how to detect them
 NOTE   : This code DOES NOT attack any system and DOES NOT transmit spoofed 
          packets over the network. All spoofing packets are simulated locally
          for academic demonstration and safety compliance.
===============================================================================
"""

from scapy.all import *
import time
from threading import Thread
from collections import defaultdict

# ===============================
# SECTION 1: PACKET SIMULATOR
# ===============================

def generate_spoofed_packets():
    """
    This function simulates spoofed packets inside the script.
    They are NOT transmitted to the network.
    They are fed internally to the detection engine for safe demonstration.
    """
    print("\n[SIMULATOR] Starting spoofed packet generator...\n")
    spoof_sources = [
        "10.0.0.99",         # Private IP spoof
        "123.45.67.89",      # Random public spoof
        "192.168.1.250",     # Internal masquerade
        "203.0.113.9",       # Documentation-range attack IP
        "198.51.100.88"      # Fake external attacker
    ]

    while True:
        src = random.choice(spoof_sources)
        pkt = IP(src=src, dst="192.168.1.10", ttl=random.randint(5, 250)) / ICMP()

        print(f"[SIMULATOR] Generated spoofed packet: src={src}")
        analyze_packet(pkt)  # Feed into detection engine

        time.sleep(1.2)  # Slow down for clarity


# ===============================
# SECTION 2: REAL‑TIME DETECTION ENGINE
# ===============================

ip_frequency = defaultdict(list)

def detect_anomalies(packet):
    alerts = []
    now = time.time()

    if IP in packet:
        src_ip = packet[IP].src
        ttl = packet[IP].ttl

        # ------------------------------
        # Rule 1: High Frequency Traffic
        # ------------------------------
        ip_frequency[src_ip].append(now)
        ip_frequency[src_ip] = [t for t in ip_frequency[src_ip] if now - t <= 5]

        if len(ip_frequency[src_ip]) > 5:
            alerts.append(f"High frequency traffic detected from {src_ip}")

        # ------------------------------
        # Rule 2: Abnormal TTL
        # ------------------------------
        if ttl < 20 or ttl > 200:
            alerts.append(f"Suspicious TTL ({ttl}) from {src_ip}")

        # ------------------------------
        # Rule 3: Private IP misuse
        # ------------------------------
        if src_ip.startswith("10.") or src_ip.startswith("192.168."):
            alerts.append(f"Possible internal spoofing attempt from {src_ip}")

        # ------------------------------
        # Rule 4: Documentation IP = simulated attacker
        # ------------------------------
        if src_ip.startswith("203.0.") or src_ip.startswith("198.51."):
            alerts.append(f"Simulated attack‑range IP detected ({src_ip})")

    return alerts


def analyze_packet(packet):
    """Print alerts in real‑time like a real IDS system."""
    alerts = detect_anomalies(packet)
    if alerts:
        print("\n===== [REAL‑TIME ALERT] Spoofing Indicators Detected =====")
        for a in alerts:
            print(f" → {a}")
        print("==========================================================\n")


# ===============================
# SECTION 3: MAIN PROGRAM
# ===============================
if __name__ == "__main__":
    print("\n==============================================================")
    print(" REAL‑TIME IP SPOOFING SIMULATION & DETECTION (SAFE + LEGAL) ")
    print("==============================================================")
    print("This system will:")
    print("  ✓ Generate artificial spoofed packets (not sent on network)")
    print("  ✓ Analyze them in real‑time")
    print("  ✓ Produce alerts like a professional intrusion detection system\n")

    # Run spoofing simulator in background
    simulator_thread = Thread(target=generate_spoofed_packets, daemon=True)
    simulator_thread.start()

    # Keep program running
    while True:
        time.sleep(1)
