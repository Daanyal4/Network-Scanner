from scapy.all import *

def scan_network(ip_range):
    devices = []
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    result = srp(packet, timeout=3, verbose=0)[0]
    
    for sent, received in result:
        devices.append({'ip':received.psrc, 'mac':received.hwsrc})
    return devices

if __name__ == '__main__':
    ip_range = "192.169.1.0/24"
    devices = scan_network(ip_range)
    print(devices)