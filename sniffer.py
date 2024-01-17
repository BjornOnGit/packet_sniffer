"""Sniff packets on a given interface and print the host name of the HTTP request."""
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    """Sniff packets on a given interface"""
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    """Process sniffed packets"""
    if packet.haslayer(http.HTTPRequest):
        print(packet[http.HTTPRequest].Host)
        print(packet.show())

sniff("wlan0")
