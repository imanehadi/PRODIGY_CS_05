#  Network Packet Analyzer

Un outil simple en Python qui capture et analyse le trafic réseau.  
Projet éducatif en cybersécurité.

##  Fonctionnalités
- Capture des paquets réseau en temps réel
- Affichage des adresses IP source et destination
- Détection des protocoles (ICMP, TCP, UDP, HTTP, DNS)
- Extraction du payload (contenu des paquets)

## Installation
Clonez le dépôt et exécutez avec Python 3 :

```bash
git clone https://github.com/ton_nom/network-packet-analyzer.git
cd network-packet-analyzer
sudo python3 sniffer.py

## Tests


Pour tester le sniffer, exécutez ces commandes dans un autre terminal :
```bash
ping 8.8.8.8 -c 4
dig google.com
curl http://example.com

## Exemple de sortie
```bash
[+] New Packet: ICMP
Source: 192.168.1.10 -> Destination: 8.8.8.8
Payload: ...

