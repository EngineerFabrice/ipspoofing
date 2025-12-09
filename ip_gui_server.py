import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, UDP

# -----------------------------
# GUI Application Class
# -----------------------------
class SpoofDetectionGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("IP Spoofing Detection Dashboard")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        # ---- Real Messages Panel ----
        tk.Label(root, text="Real Messages (Phone → PC)", fg="white", bg="#1e1e1e",
                 font=("Arial", 14, "bold")).pack()
        self.real_box = scrolledtext.ScrolledText(root, height=10, width=110,
                                                  bg="#2d2d2d", fg="lightgreen", font=("Consolas", 11))
        self.real_box.pack(pady=5)

        # ---- Spoofed Messages Panel ----
        tk.Label(root, text="Detected Spoofed Packets", fg="white", bg="#1e1e1e",
                 font=("Arial", 14, "bold")).pack()
        self.spoof_box = scrolledtext.ScrolledText(root, height=10, width=110,
                                                   bg="#2d2d2d", fg="red", font=("Consolas", 11))
        self.spoof_box.pack(pady=5)

        # ---- Log Panel ----
        tk.Label(root, text="Event Log", fg="white", bg="#1e1e1e",
                 font=("Arial", 14, "bold")).pack()
        self.log_box = scrolledtext.ScrolledText(root, height=6, width=110,
                                                 bg="#2d2d2d", fg="cyan", font=("Consolas", 11))
        self.log_box.pack(pady=5)

        # Start server + sniffer
        threading.Thread(target=self.start_udp_server, daemon=True).start()
        threading.Thread(target=self.start_sniffer, daemon=True).start()

    # -----------------------------
    # UDP Server (Receives real messages from phone)
    # -----------------------------
    def start_udp_server(self):
        host = "0.0.0.0"
        port = 9090

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((host, port))

        self.log("UDP server running on port 9090...")

        while True:
            data, addr = server.recvfrom(1024)
            msg = data.decode()
            sender_ip = addr[0]

            self.real_box.insert(tk.END, f"[PHONE MESSAGE] {msg}\n")
            self.real_box.insert(tk.END, f"[PHONE REAL IP] {sender_ip}\n\n")
            self.real_box.see(tk.END)

            self.log(f"Received real message from {sender_ip}")

    # -----------------------------
    # Real-Time Packet Sniffer
    # -----------------------------
    def start_sniffer(self):
        sniff(filter="udp and port 9090", prn=self.analyze_packet, store=False)

    # -----------------------------
    # Packet Analysis
    # -----------------------------
    def analyze_packet(self, packet):
        if IP in packet:
            src = packet[IP].src

            # Check if IP belongs to your phone
            real_phone_ip = PHONE_IP

            if src != real_phone_ip:
                # Spoofed alert
                self.spoof_box.insert(tk.END,
                    f"[SPOOF DETECTED] Packet from fake IP: {src}\n")
                self.spoof_box.see(tk.END)

                self.log(f"Alert: Spoofed packet detected from {src}")

    # -----------------------------
    # Logging function
    # -----------------------------
    def log(self, text):
        self.log_box.insert(tk.END, f"{text}\n")
        self.log_box.see(tk.END)


# -----------------------------
# MAIN PROGRAM
# -----------------------------
if __name__ == "__main__":
    # >>> SET YOUR PHONE'S IP ADDRESS HERE <<<
    PHONE_IP = "192.168.1.53"  # change to your real phone IP

    root = tk.Tk()
    app = SpoofDetectionGUI(root)
    root.mainloop()
