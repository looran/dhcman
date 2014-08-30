#!/usr/bin/env python

# dhcman - dhcp client using manual payload
# 2014, Laurent Ghigonis <laurent@gouloum.fr>

# See also:
# RFC 2131 Dynamic Host Configuration Protocol

import scapy.all as scapy
import argparse
import binascii

parser = argparse.ArgumentParser(description='dhcp client using manual payload')
parser.add_argument('iface',
                    help='interface to use')
parser.add_argument('hexpayload',
                    help='dhcpdiscover hexadecimal payload')
args = parser.parse_args()

pkt = scapy.Ether(src=scapy.get_if_hwaddr(args.iface), dst="ff:ff:ff:ff:ff:ff") \
        / scapy.IP(src="0.0.0.0", dst="255.255.255.255") \
        / scapy.UDP(sport=68, dport=67) \
        / binascii.a2b_hex(args.hexpayload)

print("Sending payload")
ans, unans = scapy.srp(pkt, iface=args.iface, timeout=2)

print("ans: %s" % ans)
print("unans: %s" % unans)
