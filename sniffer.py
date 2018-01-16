from scapy.all import *

def callback(pkt):
    if pkt.haslayer(DNSRR):
        #print pkt.summary()
        print pkt.show()
        ip = pkt['IP']
        udp = pkt['UDP']
        dns = pkt['DNS']

        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            print "[*] response: %s:%s <- %s:%d : %s - %s" % (
                  ip.dst, udp.dport,
                  ip.src, udp.sport,
                  dnsrr.rrname, dnsrr.rdata)

            if (dnsrr.rdata == '8.8.8.8'):
                dnsrr.rdata = '10.0.0.1'
                print "[*] response: %s:%s <- %s:%d : %s - %s" % (
                    ip.dst, udp.dport,
                    ip.src, udp.sport,
                    dnsrr.rrname, dnsrr.rdata) 

sniff(filter='port 53', prn=callback, store=0, iface='ens3')
