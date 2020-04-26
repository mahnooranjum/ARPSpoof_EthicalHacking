#!usr/bin/env python
import scapy.all as sp
import argparse

# run using:
# python3 spoofDetector.py -i wlan0
def get_arg(parser, flag, name, text):
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    return parser

def scan(ip):
    arp_req = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answered = sp.srp(arp_broadcast, timeout=10, verbose=False)[0]
    return answered[0][1].hwsrc

def sniff(interface):
    # Use berkeley packet filter syntax
    sp.sniff(iface = interface, store=False, prn=processing)

def processing(packet):
    # check if the response is of type is-at 
    if packet.haslayer(ap.ARP) and packet[sp.ARP].op == 2:
        try:
            real = scan(packet[sp.ARP].psrc)
            packet_mac = packet[sp.ARP].hwsrc
            
            if packet_mac != real:
                print("[INFO] ARP Spoof attack in network !")
        except IndexError:
            pass


parser = argparse.ArgumentParser()
parser = get_arg(parser, 'i', 'interface', 'Interface for sniffing for ARP spoof detection')

value = parser.parse_args()
sniff(value.interface)