#!/usr/bin/env/ python
import scapy.all as sp
def scan(ip):
    arp_req = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answered = sp.srp(arp_broadcast, timeout=10, verbose=False)[0]
    return answered[0][1].hwsrc

print(scan('192.168.1.193'))