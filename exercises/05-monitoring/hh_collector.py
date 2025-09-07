#! /usr/bin/python3

from scapy.all import *
import sys

if len(sys.argv)<2:
    print('pass 2 arguments: <report pkts>')
    exit(1)

count = int(sys.argv[1])

heavy_hitter_flows = dict()

## setup sniff, filtering for IP traffic
captured_pkts = sniff(iface="eth0", filter="ip", count=count)
print(captured_pkts)

for p in captured_pkts:
    src_ip  = str(p[IP].src)
    dst_ip  = str(p[IP].dst)
    proto   = str(p[IP].proto)
    if ICMP in p:
        src_l4 = str(0)
        dst_l4 = str(0)
    elif UDP in p:
        src_l4 = str(p[UDP].sport)
        dst_l4 = str(p[UDP].dport)
    else:
        src_l4 = str(p[TCP].sport)
        dst_l4 = str(p[TCP].dport)

    key = ','.join([src_ip, dst_ip, proto, src_l4, dst_l4])
    if key in heavy_hitter_flows:
        heavy_hitter_flows[key] = heavy_hitter_flows[key] + 1
    else:
        heavy_hitter_flows[key] = 1

print("== Reported HH Flows ==")

for k, v in heavy_hitter_flows.items():
    print(k)
    
    
