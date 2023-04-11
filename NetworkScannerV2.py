from scapy.all import *
import netifaces

def scan_network(ip_range):
    devices = []
    ip_list = []
    
    # Scan for live hosts using ARP ping
    arp_ping = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_ping_packet = broadcast/arp_ping
    arp_ping_result = srp(arp_ping_packet, timeout=3, verbose=0)[0]
    
    for sent, received in arp_ping_result:
        devices.append({'ip':received.psrc, 'mac':received.hwsrc})
    
    # Scan for all hosts in the network using ICMP ping
    icmp_ping = IP(dst=ip_range)/ICMP()
    icmp_ping_result = sr(icmp_ping, timeout=3, verbose=0)[0]
    for i in range(len(icmp_ping_result)):
        if icmp_ping_result[i].type == 0:
            ip = icmp_ping_result[i][IP].src
            if ip not in [d['ip'] for d in devices]:
                devices.append({'ip': ip})
    
    # Get the IP addresses of the local machine's network interfaces
    for interface in netifaces.interfaces():
        if_addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in if_addresses:
            ip_addresses = if_addresses[netifaces.AF_INET]
            for ip_addresses in ip_addresses:
                ip_list.append(ip_addresses['addr'])
                
    return devices, ip_list

if __name__ == '__main__':
    ip_range = "192.168.0.0/24"
    devices, ip_list = scan_network(ip_range)
    print("Devices:")
    print(devices)
    print("IP addresses:")
    print(ip_list)
