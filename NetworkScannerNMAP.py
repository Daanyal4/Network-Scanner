from scapy.all import *
import netifaces
import nmap

def is_up(ip):
    # Check if the host is up by sending an ICMP echo request and waiting for a response
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=1, verbose=0)
    if resp is not None:
        return True
    else:
        return False

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
    
    # Scan for all hosts in the network using Nmap ping sweep (-sn)
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    for ip in nm.all_hosts():
        if ip not in [d['ip'] for d in devices]:
            devices.append({'ip': ip})
    
    # Scan for all hosts in the subnet using Nmap list scan (-sL)
    nm.scan(hosts=ip_range, arguments='-sL')
    for ip in nm.all_hosts():
        if ip not in [d['ip'] for d in devices]:
            devices.append({'ip': ip})
    
    # Scan for all hosts in the network using Nmap ping scan (-sP)
    nm.scan(hosts=ip_range, arguments='-sP')
    for ip in nm.all_hosts():
        if ip not in [d['ip'] for d in devices]:
            devices.append({'ip': ip})
    
    # Get the IP addresses of the local machine's network interfaces
    for interface in netifaces.interfaces():
        if_addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in if_addresses:
            ip_addresses = if_addresses[netifaces.AF_INET]
            for ip_addresses in ip_addresses:
                ip_list.append(ip_addresses['addr'])
                
    # Add the status to each device
    for device in devices:
        if is_up(device['ip']):
            device['status'] = 'up'
        else:
            device['status'] = 'down'
    
    return devices, ip_list

if __name__ == '__main__':
    ip_range = "192.168.0.0/24"
    devices, ip_list = scan_network(ip_range)
    print("Devices:")
    print(devices)
    print("IP addresses:")
    print(ip_list)
