#####################################################################
# Ryuretic: A Modular Framework for RYU                             #
# !/ryu/ryu/app/Ryuretic/Pkt_Parse13.py                           #
# author: Jacob Cox
# Pkt_Parse13.py
# date 7 February 2016
#####################################################################
# Copyright (C) 2016 Jacob Cox - All Rights Reserved                #
# You may use, distribute and modify this code under the            #
# terms of the Ryuretic license, provided this work is cited        #
# in the work for which it is used.                                 #
# For latest updates, please visit:                                 #
#                   https://github.gatech.edu/jcox70/RyureticLabs   #
#####################################################################
"""How To Run This Program
1) Ensure you have Ryu installed.
2) Save the following files to /home/ubuntu/ryu/ryu/app/Ryuretic
    a) coupler.py
    b) NFGRD.py
    c) Pkt_Parse13.py
    d) switch_mod13.py
3) In your controller terminal type: cd ryu
4) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic/Ryuretic_Intf.py
"""
###################################################
import logging
import struct
# Standard RYU calls
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, lldp, arp, ipv4, icmp, tcp, udp, dhcp, bpdu
# Needed for Ryuretic framework 
import time

class Pkt_Parse(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(Pkt_Parse, self).__init__(*args, **kwargs)
        pktinfo = {}
    #Not yet set up to handle IPv6
    def handle_pkt(self, ev):
        pkt = {}
        pkt['t_in']= time.clock()
        pkt['msg'] = ev.msg
        pkt['dp'] = pkt['msg'].datapath
        pkt['ofproto'] = pkt['msg'].datapath.ofproto
        parser = pkt['dp'].ofproto_parser
        pkt['inport']= pkt['msg'].match['in_port']
        pkt['pkt'] = packet.Packet(pkt['msg'].data)
        pkt['eth'] = pkt['pkt'].get_protocols(ethernet.ethernet)[0]
        ether = pkt['pkt'].get_protocols(ethernet.ethernet)[0]
        #print 'Parser Ether: ', ether
        pkt['srcmac']= ether.src
        pkt['dstmac']= ether.dst
        pkt['ethtype'] = ether.ethertype
        
        arp_p = pkt['arp'] = pkt['pkt'].get_protocol(arp.arp)
        #print 'ARP: ', arp_p
        if arp_p != None:
            #pkt['arp'] = True
            pkt['srcmac'] = arp_p.src_mac
            pkt['dstmac'] = arp_p.dst_mac
            pkt['srcip'] = arp_p.src_ip
            pkt['dstip'] = arp_p.dst_ip
            pkt['hlen'] = arp_p.hlen
            pkt['plen'] = arp_p.plen
            pkt['opcode'] = arp_p.opcode
            pkt['proto'] = arp_p.proto
            pkt['hwtype'] = arp_p.hwtype
            
        ip = pkt['ip'] = pkt['pkt'].get_protocol(ipv4.ipv4)
        #print 'IPv4: ', pkt['pkt'].get_protocol(ipv4.ipv4)
        if ip != None:
            #print ip
            #pkt['ip'] = True
            pkt['srcip'] = ip.src
            pkt['dstip'] = ip.dst
            pkt['ttl'] = ip.ttl
            pkt['id'] = ip.identification
            pkt['ver'] = ip.version
            pkt['flags'] = ip.flags
            pkt['hlen'] = ip.header_length
            pkt['offset'] = ip.offset
            pkt['opt'] = ip.option
            pkt['proto'] = ip.proto
            pkt['tos'] = ip.tos
            pkt['csum'] = ip.csum

        icmp_p = pkt['icmp'] = pkt['pkt'].get_protocol(icmp.icmp)
        #print 'ICMP: ', icmp_p
        if icmp_p != None:
            #pkt['icmp'] = True
            pkt['code'] = icmp_p.code
            pkt['csum'] = icmp_p.csum
            pkt['data'] = icmp_p.data
            pkt['type'] = icmp_p.type    
        tcp_p = pkt['tcp'] = pkt['pkt'].get_protocol(tcp.tcp)
        #print tcp_p
        if tcp_p != None:
            #print pkt['tcp']
            #pkt['tcp'] = True
            pkt['ack']=tcp_p.ack
            pkt['csum'] = tcp_p.csum
            pkt['dstport'] = tcp_p.dst_port
            pkt['offset'] = tcp_p.offset
            pkt['option'] = tcp_p.option
            pkt['seq'] = tcp_p.seq
            pkt['srcport'] = tcp_p.src_port
            pkt['urgent'] = tcp_p.src_port
            pkt['winsize'] = tcp_p.window_size
            pkt['bits'] = tcp_p.bits
        udp_p = pkt['udp']= pkt['pkt'].get_protocol(udp.udp)
        print udp_p
        if udp_p != None:
            #pkt['udp'] = True
            pkt['csum'] = udp_p.csum
            pkt['dstport'] = udp_p.dst_port
            pkt['srcport'] = udp_p.src_port
            pkt['t_length'] = udp_p.total_length
        pkt['dhcp']= pkt['pkt'].get_protocol(dhcp.dhcp)
        pkt['bpdu']= pkt['pkt'].get_protocol(bpdu.bpdu)
        pkt['lldp']= pkt['pkt'].get_protocol(lldp.lldp)
        return pkt
