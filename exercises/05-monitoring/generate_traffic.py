#! /usr/bin/python3

import sys
from scapy.all import *

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def replay_pkts(iface):
    pkts = []
    with open(sys.argv[1]) as f:
        pkts = f.read()
    pkts = pkts.split('\n')

    ctr = 0
    for pkt in pkts:
        pkt = pkt.split(',')
        src_ip = pkt[0]
        dst_ip = pkt[1]
        src_port = int(float(pkt[2]))
        dst_port = int(float(pkt[3]))
        proto = int(float(pkt[4]))
        pkt =  Ether(src=get_if_hwaddr(iface), dst="08:00:00:00:02:22")
        if proto == 1:
            pkt = pkt / IP(src=src_ip, dst=dst_ip) / ICMP()
        elif proto == 6:
            pkt = pkt / IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
        else:
            pkt = pkt / IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.01)
        ctr += 1
        if ctr % 100 == 0:
            print(ctr)
    print("Done!")

def main():
    iface = get_if()
    print("sending on interface %s" % (iface))
    replay_pkts(iface)

if __name__ == '__main__':
    main()
