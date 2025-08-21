from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    print("\n=== Nouveau paquet capturé ===")
    
    # Si le paquet contient une couche IP
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"IP Source: {ip_src} -> IP Destination: {ip_dst}")
        print(f"Protocole: {proto}")

    # TCP
    if packet.haslayer(TCP):
        print(f"TCP Port Source: {packet[TCP].sport} -> Port Dest: {packet[TCP].dport}")
    
    # UDP
    if packet.haslayer(UDP):
        print(f"UDP Port Source: {packet[UDP].sport} -> Port Dest: {packet[UDP].dport}")
    
    # ICMP
    if packet.haslayer(ICMP):
        print("Protocole: ICMP")
    
    # Payload (contenu brut)
    if packet.haslayer(Raw):
        print(f"Payload (Data): {packet[Raw].load[:50]}")  # Limité à 50 octets pour affichage

# Capture les paquets
print("Démarrage du sniffer... (Ctrl+C pour arrêter)")
sniff(prn=analyze_packet, store=False)
