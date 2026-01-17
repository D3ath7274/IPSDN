#   sudo python Mininet_Topology.py

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import os


def myNetwork():

    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')

    info('*** Adding controller\n')
    controller1 = net.addController(name='controller1',
                                    controller=RemoteController,
                                    ip='127.0.0.1',
                                    protocol='tcp',
                                    port=6633,  protocols="OpenFlow13")

    info('*** Add switches\n')
    switch1 = net.addSwitch(
        'switch1', cls=OVSKernelSwitch, dpid='0000000000000001', protocols='OpenFlow13')

    info('*** Add hosts\n')
    server = net.addHost('server', cls=Host, ip='10.0.0.4', defaultRoute=None)
    victim2 = net.addHost('victim2', cls=Host,
                          ip='10.0.0.2', defaultRoute=None)
    attacker = net.addHost('attacker', cls=Host,
                           ip='10.0.0.5', defaultRoute=None)
    victim3 = net.addHost('victim3', cls=Host,
                          ip='10.0.0.3', defaultRoute=None)
    victim1 = net.addHost('victim1', cls=Host,
                          ip='10.0.0.1', defaultRoute=None)

    info('*** Add links\n')
    net.addLink(switch1, victim2)
    net.addLink(switch1, server)
    net.addLink(switch1, victim1)
    net.addLink(switch1, attacker)
    net.addLink(switch1, victim3)
    net.addNAT().configDefault()
    info('*** Starting network\n')
    net.build()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('switch1').start([controller1])

    
    os.system("ifconfig switch1-eth1 promisc")

    info('*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()