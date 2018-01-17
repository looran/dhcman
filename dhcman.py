#!/usr/bin/env python

# dhcman - dhcp client using manual payload
# 2014, 2017, Laurent Ghigonis <laurent@gouloum.fr>

# See also:
# RFC 2131 Dynamic Host Configuration Protocol

import scapy.all as scapy
import argparse
import binascii

def hexdec(x):
    return int(x, 0)

parser = argparse.ArgumentParser(description='dhcp client using manual payload')
parser.add_argument('-t',
                    dest='transactionid', action='store', type=hexdec,
                    help='transaction id')
parser.add_argument('iface',
                    help='interface to use')
parser.add_argument('type',
                    choices=['discover', 'offer', 'request', 'ack'],
                    help='DHCP message type (for Ether and IP layers setup)')
parser.add_argument('hexpayload',
                    help='hexadecimal payload')
args = parser.parse_args()

if args.transactionid:
    if len(args.hexpayload) < 16:
        argparse.error("Payload too short to modify transaction id")
    args.hexpayload = args.hexpayload[:8] + "%.8x" % args.transactionid + args.hexpayload[16:]
    print("Modified payload with transaction id:\n%s" % args.hexpayload)

if args.type == 'discover' or args.type == 'request':
    pkt = scapy.Ether(src=scapy.get_if_hwaddr(args.iface), dst="ff:ff:ff:ff:ff:ff") \
            / scapy.IP(src="0.0.0.0", dst="255.255.255.255") \
            / scapy.UDP(sport=68, dport=67) \
            / binascii.a2b_hex(args.hexpayload)
elif args.type == 'offer' or args.type == 'ack':
    pkt = scapy.Ether(src=scapy.get_if_hwaddr(args.iface), dst="ff:ff:ff:ff:ff:ff") \
            / scapy.IP(src=scapy.get_if_addr(args.iface), dst="255.255.255.255") \
            / scapy.UDP(sport=67, dport=68) \
            / binascii.a2b_hex(args.hexpayload)

print("[+] Sending payload")
ans, unans = scapy.srp(pkt, iface=args.iface, timeout=2)

print("ans: %s" % ans)
print("unans: %s" % unans)
