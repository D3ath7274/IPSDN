#   python Normal_TCP.py -s start_ip -e end_ip
"""
Normal UDP traffic to the subnet with the rate of 5 packets per second.
Send [5,10] packets per random host for 500 times, 5 packets per second, total=[2500,5000].
"""

import sys
import getopt
import time
from os import popen
from scapy.all import sendp, IP, Ether, TCP
from random import randint
import random
from random import randint
import string


def sourceIPgen():
    blacklist = [10, 127, 254, 255, 1, 2, 169, 172, 192]

    first = randint(1, 255)

    while first in blacklist:
        first = randint(1, 255)

    ip = ".".join([str(first), str(randint(1, 255)), str(
        randint(1, 255)), str(randint(1, 255))])
    return ip


def gendest(start, end):
    first = 10
    second = 0
    third = 0
    ip = ".".join([str(first), str(second), str(
        third), str(randint(start, end))])
    return ip


def main():
    start = 1
    end = 5

    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:e:', ['start=', 'end='])
    except getopt.GetoptError:
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-s':
            start = int(arg)
        elif opt == '-e':
            end = int(arg)
    if start == '':
        sys.exit()
    if end == '':
        sys.exit()

    interface = popen('ip link show | grep "eth0:" | awk \'{print $2}\' | tr -d ":"\'').read()
    if not interface.strip():
        interface = popen('ifconfig | grep "eth0" | awk \'{print $1}\'').read()

    payload = ""

    for i in range(500):
        payload = "".join(random.choice(string.ascii_uppercase + string.digits +
                          string.ascii_lowercase) for x in range(randint(10, 40)))

        packets = Ether()/IP(dst=gendest(start, end), src=sourceIPgen()) / \
            TCP(dport=80, sport=2) / payload
        print(repr(packets))

        for j in range(randint(5,10)):
            sendp(packets, iface=interface.rstrip(), inter=0.2)


if __name__ == "__main__":
    main()
