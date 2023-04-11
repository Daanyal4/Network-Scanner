from scapy.all import *
import netifaces

def scan_network(ip_range):
    devices = []
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    result = srp(packet, timeout=3, verbose=0)[0]
    
    for sent, received in result:
        devices.append({'ip':received.psrc, 'mac':received.hwsrc})
    
    ip_list = []
    for interface in netifaces.interfaces():
        if_addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in if_addresses:
            ip_addresses = if_addresses[netifaces.AF_INET]
            for ip_addresses in ip_addresses:
                ip_list.append(ip_addresses['addr'])
                
    return devices, ip_list

if __name__ == '__main__':
    ip_range = "192.169.175.0/24"
    devices, ip_list = scan_network(ip_range)
    print("Devices:")
    print(devices)
    print("IP addresses:")
    print(ip_list)