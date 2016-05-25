#####################################################################
# Ryuretic: A Modular Framework for RYU                             #
# !/mininet/examples/Ryuretic/RyureticTestBed.py                    #
# Author:                                                           #
#   Jacob Cox (jcox70@gatech.edu)                                   #                             #
# RyureticTestBed.py                                                #
# Date: 23 May 2016                                                 #
#####################################################################
# Copyright (C) 1883 Thomas Edison - All Rights Reserved            #
# You may use, distribute and modify this code under the            #
# terms of the Ryuretic license, provided this work is cited        #
# in the work for which it is used.                                 #
# For latest updates, please visit:                                 #
#                   https://github.gatech.edu/jcox70/???   #
#####################################################################
###################################################
#!/usr/bin/python
#!/mininet/examples/SecFrameTest
# author: Jacob Cox
# Security_Rev_TestBed.py
# date 30 July 2015
###################################################
"""How To Run This Program """
###################################################
"""
This program sets up a mininet architecture consisting of one NAT router,
one switch, one dhcp server, and 6 hosts. IPs are only assigned to the
NAT router and the DHCP server. Hosts are not assigned IPs until a dhclient
request is made to obtain IPS from the DHCP server.
"""
#Program requirements
"""
"""
#Instructions:
"""
1)  a) sudo mn -c
    b) sudo python Security_Rev_TestBed.py
2) To shutdown:
    a) In terminal 2, hit cntl+c (exit pyretic controller)
    b) In terminal 1, type exit
    c) In terminal 1, type sudo mn -c
"""

"""
                     CNTRL           
                       |             
    ----------------SWITCH-----------NAT                
    |      |        |       |
  NAT1     H1       H2      H3
    |
 ---------
 |       |
 H4      H5

"""

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
        '''
        nat+--+              +-----------+h1
              |              +-----------+h2
              +-------+s1+---+-----------+h3
                             +-----------+NAT+---+---+h4
                                                 +---+h5

        '''
        # Initialize topo
        Topo.__init__(self, **params)
        ###Thanks to Sean Donivan for the NAT code####
        natIP= '10.0.0.222'
        rogueNAT = '192.168.1.1' 
        # Host and link configuration
        hostConfig = {'cpu': cpu, 'defaultRoute': 'via ' + natIP }
        hostNat = {'defaultRoute': 'via ' + rogueNAT}
        LinkConfig = {'bw': 10, 'delay': '1ms', 'loss': 0,
                   'max_queue_size': max_queue_size }
        #################################################
        print "Adding Switch"
        #add Single Switch
        s1  = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2')

        print "Adding h1, h2, and h3; connecting to Switch"
        #add six hosts with IP assigned 
        h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip="10.0.0.1", **hostConfig)
        self.addLink(s1, h1, 1, 1, **LinkConfig)
        
        h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip="10.0.0.2", **hostConfig)
        self.addLink(s1, h2, 2, 1, **LinkConfig)
        
        h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip="10.0.0.3", **hostConfig)
        self.addLink(s1, h3, 3, 1, **LinkConfig)
        
        # Create and add NAT
        print "Building NAT"
        self.nat = self.addNode( 'nat', cls=NAT, mac='00:00:00:00:0A:AC', ip=natIP,
                            inNamespace=False)	
        self.addLink(s1, self.nat, port1=8 )

        # Create and add Rogue NAT

        self.nat1 = self.addNode( 'nat1', cls=NAT, mac='00:00:00:00:11:22',
                                  ip='10.0.0.14',
                                  subnet='192.168.1.0/24',
                                  inetIntf='nat1-eth0', localIntf='nat1-eth1',
                                  **hostConfig)
        self.addLink(s1, self.nat1, port1=4)
        natParams = {'ip' : '192.168.1.1/24'}
        self.addLink(s2, self.nat1,intfName1='nat1-eth1', params1=natParams)


        print "Connecting h4 and h5 to Rogue NAT"
        # add host and connect to the Rogue NAT
        h4 = self.addHost('h4', mac='00:00:00:00:11:00',
                          ip='192.168.1.100/24',defaultRoute='via 192.168.1.1')
        h5 = self.addHost('h5', mac='00:00:00:00:11:01',
                          ip='192.168.1.101/24', defaultRoute='via 192.168.1.1')
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        


    


if __name__ == '__main__':
    info('*** Starting Mininet *** \n')
    print '*** Starting Mininet *** \n'
    topo = RevocationTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController)
    info('*** Topology Created *** \n')
    print "***Toplology Created***"
    
    net.start()
    run("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    

    info('***attempting to start dhcp server***')
    #net.get('dhcp1').cmd('sudo /etc/init.d/isc-dhcp-server start')
    #net.get('dhcp1').cmd('sudo wireshark &')
    #info('***Starting Wireshark...*** \n')
    #raw_input("\nPress Enter once Wireshark is capturing trafic \n")
    #info('*** Assigning IP to h1 and h2 (See Wireshark) *** \n')
    #net.get('h1').cmd('dhclient')
    #net.get('h2').cmd('dhclient')
    info('*** Running CLI *** \n')
    net.get('nat1').cmd('ifconfig nat1-eth1 192.168.1.1')
    print '***Starting CLI *** \n'
    CLI( net )

    info ('*** Stopping Network ***')
    #net.get('dhcp1').cmd('sudo /etc/init.d/isc-dhcp-server stop')
    net.stop()
