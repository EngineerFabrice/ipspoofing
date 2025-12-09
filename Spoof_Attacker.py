from scapy.all import IP, UDP, send

fake_ips = ["192.168.1.250", "10.10.10.99", "203.0.113.9"]

target_ip = "192.168.1.20"   # your PC IP
target_port = 9090

for ip in fake_ips:
    packet = IP(src=ip, dst=target_ip) / UDP(dport=target_port) / b"SPOOFED_PACKET"
    print(f"[ATTACK SIM] Sending spoofed packet from {ip}")
    send(packet, verbose=0)

print("[DONE] Spoof simulation completed.")
