"""
This module implements a packet sniffer that captures and prints network packets.
"""

import socket
import struct
import sys
import tkinter as tk
import pcapy
from scapy.all import *


def capture_packets():
    """
    The main function that captures and prints network packets.
    """
    try:
        cap = pcapy.open_live(interface, 65536, 1, 0)
        cap.setnonblock(1)
    except Exception as e:
        print(f"Error opening interface: {str(e)}")
        sys.exit()

    save_file = "captured_packets.txt"

    with open(save_file, "wb") as capture_file:
        while True:
            try:
               header, data = cap.next()
               eth = data

               if len(data) < 14:
                    print("Malformed packet: Data length is less than 14 bytes")
                    continue
               
               eth_header = struct.unpack("!6s6s2s", data[:14])
               if eth_header[2] == b'\x08\x00':
                    ip = data[14:34]

                    if len(ip) < 20:
                        print("Malformed IP packet: Data length is less than 20 bytes")
                        continue

                    ip_header = struct.unpack("!BBHHHBBH4s4s", ip)

                    source_ip = socket.inet_ntoa(ip_header[8])
                    destination_ip = socket.inet_ntoa(ip_header[9])

                    # Check if the IP packet contains a TCP header
                    if ip_header[6] == 6:
                        tcp = data[34:54]

                        if len(tcp) < 20:
                            print("Malformed TCP packet: Data length is less than 20 bytes")
                            continue

                        tcp_header = struct.unpack("!HHLLBBHHH", tcp)
                        protocol = "TCP"

                        if tcp_header[1] == 80:
                            http_data = data[54:]  # Assuming payload starts at byte 54

                            # Display the HTTP payload data
                            print(f"HTTP Payload:\n{http_data.decode('utf-8')}")

                    # Check if the IP packet contains a UDP header
                    elif ip_header[6] == 17:
                        udp = data[34:42]

                        if len(udp) < 8:
                            print("Malformed UDP packet: Data length is less than 8 bytes")
                            continue

                        udp_header = struct.unpack("!HHHH", udp)
                        protocol = "UDP"

                    packet_info = f"Source IP: {source_ip}\n" \
                                  f"Destination IP: {destination_ip}\n" \
                                  f"Protocol: {protocol}\n"

                    # Update the GUI with the packet information
                    text_box.insert(tk.END, packet_info)
                    text_box.insert(tk.END, "====================================\n")
                    
                    capture_file.write(data)

            except KeyboardInterrupt:
                print("Exiting...")
                break
            except socket.error as e:
                print(f"Socket Error: {str(e)}")

def capture_wireless_packets():
    """ Captures wireless packets and prints the SSID, BSSID, and signal strength"""
    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            ssid = pkt.getlayer(Dot11).info
            bssid = pkt.getlayer(Dot11).addr2
            signal_strength = -(256 - ord(pkt.notdecoded[-4:-3]))

            packet_info = f"SSID: {ssid}\n" \
                          f"BSSID: {bssid}\n" \
                          f"Signal Strength: {signal_strength} dBm\n"

            text_box.insert(tk.END, packet_info)
            text_box.insert(tk.END, "====================================\n")

    try:
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print("Exiting...")
    except OSError as e:
        print(f"Error capturing wireless packets: {str(e)}")

# Specify the network interface for both wired and wireless capture
interface = "eth0"  # Replace with the appropriate network interface

# Create a simple Tkinter GUI
root = tk.Tk()
root.title("Packet Sniffer")

text_box = tk.Text(root)
text_box.pack()

# Button to capture packets from wired network
capture_wired_button = tk.Button(root, text="Capture Wired Packets", command=capture_packets)
capture_wired_button.pack()

# Button to capture packets from wireless network
capture_wireless_btn = tk.Button(root, text="Capture Wireless Packets", command=capture_wireless_packets)
capture_wireless_btn.pack()

root.mainloop()
