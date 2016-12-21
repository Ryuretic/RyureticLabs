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
from ryu.lib.packet import ethernet, lldp, arp, ipv4, icmp
from ryu.lib.packet import bpdu, ipv6, tcp, udp, icmpv6, dhcp


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
        pkt['t_in']= int(round(time.time() *1000)) #time.clock()
        pkt['msg'] = ev.msg
        pkt['dp'] = pkt['msg'].datapath
        pkt['ofproto'] = pkt['msg'].datapath.ofproto
        parser = pkt['dp'].ofproto_parser
        pkt['inport']= pkt['msg'].match['in_port']
        pkt['pkt'] = packet.Packet(pkt['msg'].data)
        #pkt['eth']
        #ether = pkt['eth'] = pkt['pkt'].get_protocols(ethernet.ethernet)[0]
        
        ether = pkt['eth'] = pkt['pkt'].get_protocols(ethernet.ethernet)[0]
        pkt['srcmac']= ether.src
        pkt['dstmac']= ether.dst
        pkt['ethtype'] = ether.ethertype

        
        arp_p = pkt['arp']= pkt['pkt'].get_protocol(arp.arp)
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

        #Adding DHCP packet support
        dhcp_p = pkt['dhcp'] = pkt['pkt'].get_protocol(dhcp.dhcp)
        #print dhcp_p
        if dhcp_p != None:
            #print "DHCP ", dhcp_p
            pkt['dhcp_bt_file']=dhcp_p.boot_file
            pkt['dhcp_chaddr']=dhcp_p.chaddr
            pkt['dhcp_ciaddr']=dhcp_p.ciaddr
            pkt['dhcp_flags']=dhcp_p.flags
            pkt['dhcp_giaddr']=dhcp_p.giaddr
            pkt['dhcp_hlen']=dhcp_p.hlen
            pkt['dhcp_hops']=dhcp_p.hops
            pkt['dhcp_htype']=dhcp_p.htype
            pkt['dhcp_op']=dhcp_p.op
            pkt['dhcp_options']=dhcp_p.options
            pkt['dhcp_secs']=dhcp_p.secs
            pkt['dhcp_siaddr']=dhcp_p.siaddr
            pkt['dhcp_sname']=dhcp_p.sname
            pkt['dhcp_xid']=dhcp_p.xid
            pkt['dhcp_yiaddr']=dhcp_p.yiaddr
            print pkt['dhcp']
            
            
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

        #Adding IPv6 packet support
        ip6 = pkt['ip6'] = pkt['pkt'].get_protocol(ipv6.ipv6) #New
        if ip6 != None:
            pkt['ip6_vers'] = ip6.version
            pkt['ip6_traf_cls'] = ip6.traffic_class
            pkt['ip6_flw_lbl'] = ip6.flow_label
            pkt['ip6_pl_len'] = ip6.payload_length
            pkt['ip6_nxt'] = ip6.nxt
            pkt['ip6_hp_lim'] = ip6.hop_limit
            pkt['ip6_srcip'] = ip6.src
            pkt['ip6_dstip'] = ip6.dst
            pkt['ip6_ext_hdrs'] = ip6.ext_hdrs

        icmp_p = pkt['icmp'] = pkt['pkt'].get_protocol(icmp.icmp)
        #print 'ICMP: ', icmp_p
        if icmp_p != None:
            #pkt['icmp'] = True
            pkt['code'] = icmp_p.code
            pkt['csum'] = icmp_p.csum
            pkt['data'] = icmp_p.data
            pkt['type'] = icmp_p.type

        #Adding ICMPv6 packet support
        icmp6 = pkt['icmp6'] = pkt['pkt'].get_protocol(icmpv6.icmpv6) #New
        #print icmp6
        if icmp6 != None:
            #print icmp6
            pkt['icmp6_type'] = icmp6.type_
            pkt['icmp6_code'] = icmp6.code
            pkt['icmp6_csum'] = icmp6.csum
            #pkt['icmp6_data']
            x = icmp6.data
            if pkt['icmp6_type'] == 133:
                pkt['icmp6_res'] = x.res
                x1 = x.option
                pkt['icmp6_hw_src'] = x1.hw_src
                pkt['icmp6_length'] = x1.length
                pkt['icmp6_data'] = x1.data
            elif pkt['icmp6_type'] == 143:
                pkt['icmp6_r_num'] = x.record_num
                pkt['icmp6_aux'] = x.records[0].aux
                pkt['icmp6_address'] = x.records[0].address
                pkt['icmp6_aux_len'] = x.records[0].aux_len
                pkt['icmp6_num'] = x.records[0].num
                pkt['icmp6_srcs'] = x.records[0].srcs
            elif pkt['icmp6_type'] == 135:
                pkt['icmp6_dst'] = x.dst
                pkt['icmp6_option'] = x.option
                pkt['icmp6_res'] = x.res
            else:
                print "+++=============Unknown IPv6================+++"
                print pkt['data']                    

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
        #print udp_p
        if udp_p != None:
            #pkt['udp'] = True
            pkt['csum'] = udp_p.csum
            pkt['dstport'] = udp_p.dst_port
            pkt['srcport'] = udp_p.src_port
            pkt['t_length'] = udp_p.total_length
        pkt['bpdu']= pkt['pkt'].get_protocol(bpdu.bpdu)
        pkt['lldp']= pkt['pkt'].get_protocol(lldp.lldp)
        return pkt



##
##            print 'Batch File: ',pkt['dhcp_bt_file']
##            print 'CHADDR: ',pkt['dhcp_chaddr']
##            print 'CIADDR: ',pkt['dhcp_ciaddr']
##            print 'Flags: ',pkt['dhcp_flags']
##            print 'GIADDR: ',pkt['dhcp_giaddr']
##            print 'HLEN: ',pkt['dhcp_hlen']
##            print 'Hops: ',pkt['dhcp_hops']
##            print 'Htype: ',pkt['dhcp_htype']
##            print 'Op: ',pkt['dhcp_op']
##            print 'Options: ',pkt['dhcp_options']
##            print 'Secs: ',pkt['dhcp_secs']
##            print 'siaddr: ',pkt['dhcp_siaddr']
##            print 'Sname: ',pkt['dhcp_sname']
##            print 'Xid: ',pkt['dhcp_xid']
##            print 'Yid: ',pkt['dhcp_yiaddr']           

    
