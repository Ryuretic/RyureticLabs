#########################################################################
# Ryuretic: A Modular Framework for RYU                                 #
# !/mininet/examples/Ryuretic/RogueNAT.py                               #
# Author:                                                               #
#   Jacob Cox (jcox70@gatech.edu)                                       #       
# RogueNAT.py                                                           #
# Date: 23 May 2016                                                     #
#####################################################################
# Copyright 2016, Jacob Cox, All rights reserved.                       #
# You may use, distribute and modify this code under the                #
# terms of the Ryuretic license, provided this work is cited            #
# in the work for which it is used.                                     #
# For latest updates, please visit:                                     #
#               https://github.gatech.edu/jcox70/RyureticLabs           #
#########################################################################
"""How To Run This Program 
This program sets up a mininet architecture consisting of one NAT router,
one switch, one rogue NAT, 3 visible hosts, and 2 hidden hosts.

This code was developed in the sdnhub.ova virtual machine. See above link
"""
#########################################################################
#Instructions:
"""
1)  a) Best to turn controller on first.
    b) sudo mn -c
    c) sudo python mininet/examples/Ryuretic/RogueNat2.py
2) To shutdown:
    a) In terminal, type exit
    c) In terminal, type sudo mn -c
"""
#########################################################################

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.util import custom
from mininet.node import RemoteController,OVSSwitch
from mininet.log import setLogLevel, info
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.util import run


#Topology to be instantiated in Mininet
class RevocationTopo(Topo):
    "Mininet Security Rev Test topology"
    
    def __init__(self, cpu=.1, max_queue_size=None, **params):
        print'''
               CNTRL+-+    
       nat+--+        |    +-----------+h1 
             |        +    +-----------+h2
             +------+s1+---+-----------+h3
                           +-----------+nat1+---+h4
                                            +---+h5
        '''
        # Initialize topo
        Topo.__init__(self, **params)
        ###Thanks to Sean Donivan for the NAT code####
        natIP= '10.0.0.254'
        rogueNAT = '192.168.1.1' 
        # Host and link configuration
        hostConfig = {'cpu': cpu, 'defaultRoute': 'via ' + natIP }
        hostNat = {'defaultRoute': 'via ' + rogueNAT}
        LinkConfig = {'bw': 10, 'delay': '1ms', 'loss': 0,
                   'max_queue_size': max_queue_size }

        print "*** Adding Switch ***\n"
        #add Single Switch
        s1  = self.addSwitch('s1', protocols='OpenFlow13')
        #s2 = self.addSwitch('s2')

        print "*** Adding hosts (h1, h2, and h3) ***"
        print "*** Linking hosts to s1 ***"
        #add six hosts with IP assigned 
        h1 = self.addHost('h1', mac='01:01:01:01:01:01',
                          ip="10.0.0.1", **hostConfig)#MAC doesn't match
        self.addLink(s1, h1, 1, 1, **LinkConfig)
        
        h2 = self.addHost('h2', mac='00:00:00:00:00:02',
                          ip="10.0.0.2", **hostConfig)
        self.addLink(s1, h2, 2, 1, **LinkConfig)
        
        h3 = self.addHost('h3', mac='00:00:00:00:00:03',
                          ip="10.0.0.3", **hostConfig)
        self.addLink(s1, h3, 3, 1, **LinkConfig)
        
        # Create and add NAT
        print "*** Building NAT for Internet Access ***"
        self.nat = self.addNode( 'nat', cls=NAT,
                                 mac='00:00:00:00:0A:AA', ip=natIP,
                                 inNamespace=False)	
        self.addLink(s1, self.nat, port1=8 )

        # Create and add Rogue NAT
        print "*** Creating Rogue NAT (nat1) ***\n"
        self.nat1 = self.addNode( 'nat1', cls=NAT, mac='00:00:00:00:0B:AD',
                                  ip='10.0.0.14',
                                  inetIntf='nat1-eth0',
                                  subnet='192.168.1.0/24',
                                  localIntf= 'nat1-eth1',
                                  subnet1 = '192.168.2.0/24',
                                  localIntf1 = 'nat1-eth2',
                                  **hostConfig)
        
        print "*** Connecting Rogue NAT (nat1) to switch (s1) ***"
        self.addLink(s1, self.nat1, port1=4)
        natParams = {'ip' : '192.168.1.1/24'}
        natParams2 = {'ip' : '192.168.2.1/24'}

        print "*** Creating hosts h4 and h5 ***"
        
        # add host and connect to the Rogue NAT
        h4 = self.addHost('h4', mac='00:00:00:44:44:44',
                          ip='192.168.1.100/24',
                          defaultRoute='via 192.168.1.1')
        h5 = self.addHost('h5', mac='00:00:00:55:55:55',
                          ip='192.168.2.100/24',
                          defaultRoute = 'via 192.168.2.1')
        
        print "*** Linking h4 and h5 to Rogue NAT ***" 
        self.addLink(h4, self.nat1, intfName1='nat1-eth1', params1=natParams)
        self.addLink(h5, self.nat1, intfName2='nat1-eth2', params2=natParams2)
 
        
if __name__ == '__main__':
    #info('*** Starting Mininet *** \n')
    print '*** Starting Mininet *** \n'
    topo = RevocationTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController)
    #info('*** Topology Created *** \n')
    print "*** Toplology Created*** \n"
    
    net.start()
    run("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    
    #info('*** Running CLI *** \n')
    print "*** Running CLI *** \n"
    # if the nat1-eth2 interface needs to be created, uncomment below line.
    #net.get('nat1').cmd('echo "iface nat1-eth2 inet manual" >> /etc/network/interfaces ')
    print "*** Assigning IPs to nat1-eth1 and nat1-eth2 ***"
    net.get('nat1').cmd('ifconfig nat1-eth1 192.168.1.1')
    net.get('nat1').cmd('ifconfig nat1-eth2 192.168.2.1')
    ##IPTABLE Config
    print "*** Configuring IP Tables for nat1 (allowing second interface)."
    net.get('nat1').cmd( 'iptables -P INPUT ACCEPT' )
    net.get('nat1').cmd( 'iptables -P OUTPUT ACCEPT' )
    net.get('nat1').cmd( 'iptables -P FORWARD DROP' )
    net.get('nat1').cmd('sysctl net.ipv4.ip_forward=0' )
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth1 -o nat1-eth0 -m state '+
                        '-state NEW,ESTABLISHED,RELATED -j ACCEPT')
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth1 -o nat1-eth0 -m state '+
                        '--state NEW,ESTABLISHED,RELATED -j ACCEPT')
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth0 -d 192.168.2.0/24 -j ACCEPT')
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth1 -d 192.168.2.0/24 -j ACCEPT')
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth2 -s 192.168.2.0/24 -j ACCEPT')
    net.get('nat1').cmd('iptables -A FORWARD -i nat1-eth2 -d 192.168.1.0/24 -j ACCEPT')
    net.get('nat1').cmd('iptables -I FORWARD -i nat1-eth2 -d 192.168.2.0/24 -j DROP')
    net.get('nat1').cmd('iptables -t nat -A POSTROUTING -o nat1-eth0 -s 192.168.2.0/24 -j MASQUERADE ')
    net.get('nat1').cmd( 'sysctl net.ipv4.ip_forward=1' )
    net.get('nat1').cmd('/etc/init.d/networking restart')
    net.get('nat1').cmd('service network-manager restart')
    

    CLI( net )

    info ('*** Stopping Network ***')
    print '*** Stopping CLI ***\n'
    
    net.stop()


#REFERENCES:
    # IPTABLES:
    """
        [1] https://www.linux.com/learn/linux-routing-subnets-tips-and-tricks
        [2] .../mininet/nodelib.pby
    """
        


