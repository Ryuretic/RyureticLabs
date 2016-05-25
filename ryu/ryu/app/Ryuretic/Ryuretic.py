#####################################################################
# Ryuretic: A Modular Framework for RYU                             #
# !/ryu/ryu/app/SecRevCntrl/Ryuretic.py                             #
# Authors:                                                          #
#   Jacob Cox (jcox70@gatech.edu)                                   #
#   Sean Donovan (sdonovan@gatech.edu)                              #
# Ryuretic.py                                                       #
# date 25 April 2016                                                #
#####################################################################
# Copyright (C) 1883 Thomas Edison - All Rights Reserved            #
# You may use, distribute and modify this code under the            #
# terms of the Ryuretic license, provided this work is cited        #
# in the work for which it is used.                                 #
# For latest updates, please visit:                                 #
#                   https://github.gatech.edu/jcox70/SecRevFramework#
#####################################################################
"""How To Run This Program
1) Ensure you have Ryu installed.
2) Save the following files to /home/ubuntu/ryu/ryu/app/
    a) Ryuretic_Intf.py
    b) Ryuretic.py
    c) Pkt_Parse.py
    d) switch_mod.py
2) In your controller terminal type: cd ryu
3) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic_Intf.py
"""
######################################################################
import logging
import struct
# Ryuretic framework files
from Pkt_Parse13 import Pkt_Parse
from switch_mod13 import SimpleSwitch
# Standard RYU calls
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3 as ofproto #added
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet,ipv4,arp,icmp,tcp,udp

class coupler(app_manager.RyuApp):
    ''' This is the key to ryuretic: users should subclass the coupler
    in order to write their own programs. Look at the functions below:
    their definitions describe what should be done with each of the
    functions, and will note whether or not that function is optional
    to override. '''
    OFP_VERSIONS = [ofproto.OFP_VERSION] #ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(coupler, self).__init__(*args, **kwargs)
        
        #modules are added to the coupler as objects
        self.switch=SimpleSwitch()

    def get_proactive_rules(self,dp,parser,ofproto):
        ''' Proactive rules are installed here. By default, there are no 
        proactive rules. Users of Ryuretic should override this function if they
        have proactive rules to be installed. Optional.'''

        return None, None

    ######################################################################## 
    #This decorator calls initial_event for packet arrivals
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def initial_event(self,ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        #Call <Pkt_Parse> to Build pkt object
        parsPkt = Pkt_Parse()
        pkt = parsPkt.handle_pkt(ev)
        
        # Call appropriate handler for arriving packets (add IPv6,DHCP,etc.)
        if pkt['udp'] != None:
            self.handle_udp(pkt)
        elif pkt['tcp'] != None:
            self.handle_tcp(pkt)
        elif pkt['icmp'] != None:
            self.handle_icmp(pkt)
        elif pkt['ip']!= None:
            self.handle_ip(pkt)
        elif pkt['arp']!=None:
            self.handle_arp(pkt)
        elif pkt['eth'] != None:
            self.handle_eth(pkt)
        else:
            print "Packet not identified"
            self.handle_unk(pkt)

    # The following functions all must be overridden. Some may be able to be
    # passed, but most will likely be overridden.

    def handle_eth(self,pkt):
        raise NotImplementedError("handle_eth must be overridden by child.")

    def handle_arp(self,pkt):
        raise NotImplementedError("handle_arp must be overridden by child.")

    def handle_ip(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_icmp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_tcp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_udp(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")

    def handle_unk(self,pkt):
        raise NotImplementedError("handle_ip must be overridden by child.")


    ##################################################################
    # Supporting Code
    ##################################################################
    #Initialize switch to send all packets to controller (lowest priority)
    # Adds a Table-miss flow entry (see page 8 of "Ryu: Using OpenFlow 1.3"
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print "Received Switch features"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	self.add_flow(datapath, 0, match, actions)
        ############################################################
	"""Now decide whether to add proactive flows or not"""

	fields, ops = self.get_proactive_rules(datapath,parser,ofproto)
        if (fields is not None) and (ops is not None):
            self._add_proactive_flow(datapath, parser, ofproto, fields, ops)
        ################################################################
            
    def _bld_match_vals(self, fields):
        match_vals = {}     
        fields_keys = fields['keys']
        if 'inport' in fields_keys:
            match_vals['in_port'] = fields['inport']
        if 'ethtype' in fields_keys:
            match_vals['eth_type'] = fields['ethtype']
        if 'srcmac' in fields_keys:
            match_vals['eth_src'] = fields['srcmac']
        if 'dstmac' in fields_keys:
            match_vals['eth_dst'] = fields['dstmac']
        if 'srcip' in fields_keys:
            match_vals['ipv4_src']= fields['srcip']
        if 'dstip' in fields_keys:
            match_vals['ipv4_dst'] = fields['dstip']
        if 'proto' in fields_keys:
            match_vals['ip_proto'] = fields['proto']
        if 'srcport' in fields_keys:
            match_vals['tcp_src'] = fields['srcport']
        if 'dstport' in fields_keys:
            match_vals['tcp_dst'] = fields['dstport']
        if 'data' in fields_keys:
            match_vals['data'] = fields['data']
        return match_vals        

    def _add_proactive_flow(self, datapath, parser, ofproto, fields,ops):
        actions = []
        if ops['op'] == 'drop':
            out_port = ofproto.OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
        if ops['op'] == 'redir':
            out_port = ops['newport']
            actions.append(parser.OFPActionOutput(out_port))

        match_vals = self._bld_match_vals(fields)
        
        match = parser.OFPMatch(**match_vals)
        self.add_flow(datapath, ops['priority'], match, actions)
    
    ########################################################################
    # Adds flow to the switch so future packets aren't sent to the cntrl 
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)    
       
    ########################################################################
    # Adds flow to the switch so future packets are not sent to the
    # controller (requires priority, idle_t, and hard_t)
    def add_timeFlow(self, dp, ops, match, actions):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
            
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        print "line 210 here are match", match 
        print "line 211 here are instructions", inst
        #fix switch mod to address 'idle_t'
        mod = parser.OFPFlowMod(datapath=dp,
                            priority=ops['priority'],
                            idle_timeout=ops['idle_t'],
                            hard_timeout=60,
                            match=match, instructions=inst)
        print "line 218. Mod send to switch: \n", mod
        dp.send_msg(mod)
		
    ############################################################    
    # Choose the field and ops having the highest priority and assert it.    
    def _build_FldOps(xfields,xops):
        priority = 0
        for x in len(xfields):
            if xfields[x]['priority'] > priority:
                fields,ops = xfields[x],xops[x]
        return fields,ops  
               
    ##############################################################        
    #Imeplement mac-learning (switch_mod13.py) for ethernet packets.  
    def install_field_ops(self, pkt, fields, ops):
        #Build match from pkt and fields
        match = self.pkt_match(fields)
        print "Match Fields are:   ", match
		#Build actions from pkt and ops
        out_port, actions = self.pkt_action(pkt,ops,fields)
        priority = ops['priority']
        msg = fields['msg']                          
        parser, ofproto = fields['dp'].ofproto_parser, fields['ofproto']
        
        # install temporary flow to avoid future packet_in. 
        # idle_t and hard_t must be set to something. 
##        if ops['idle_t']: # or ops['hard_t']:
##            if out_port != ofproto.OFPP_FLOOD:
##                print "Line 244: ", actions
##                self.add_timeFlow(fields['dp'], ops, match, actions)

        # For ping and wget, data = None
        data = None
        try:
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
        except:
            pass
        
        out = parser.OFPPacketOut(datapath=fields['dp'],
                                  buffer_id=msg.buffer_id,
                                  in_port=fields['inport'],
                                  actions=actions, data=data)

        #print "line 255 out: ", out
        fields['dp'].send_msg(out)

    #############################################################
    #Use fields to build match
    def pkt_match(self, fields):
        def build_match(fields):
            match_vals = {}     
            #fields_keys = fields.keys()
            #print "FIELDS ARE: ", fields
            fields_keys = fields['keys']
            if 'inport' in fields_keys:
                match_vals['in_port'] = fields['inport']
            if 'ethtype' in fields_keys:
                match_vals['eth_type'] = fields['ethtype']
            if 'srcmac' in fields_keys:
                match_vals['eth_src'] = fields['srcmac']
            if 'dstmac' in fields_keys:
                match_vals['eth_dst'] = fields['dstmac']
            if 'srcip' in fields_keys:
                match_vals['ipv4_src']= fields['srcip']
            if 'dstip' in fields_keys:
                match_vals['ipv4_dst'] = fields['dstip']
            if 'proto' in fields_keys:
                match_vals['ip_proto'] = fields['proto']
            if 'srcport' in fields_keys:
                match_vals['tcp_src'] = fields['srcport']
            if 'dstport' in fields_keys:
                match_vals['tcp_dst'] = fields['dstport']
            if 'data' in fields_keys:
                match_vals['data'] = fields['data']
            #print match_vals
            return match_vals
        
        parser = fields['dp'].ofproto_parser
        #match_vals = {}
        match_vals = build_match(fields)
        #print match_vals
        match = parser.OFPMatch(**match_vals)        
        return match

    ###############################################################
    #Determine action to be taken on packet ops={'op':None, 'newport':None}
    #User can forward , drop, redirect, mirror, or craft packets. 
    def pkt_action(self,pkt,ops,fields):
        print"********************\npacket action\n*****************"
        actions = []
        print "line 305. Ops: ", ops
        parser = fields['dp'].ofproto_parser
        if ops['op'] == 'fwd':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'drop':
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'redir':
            out_port = ops['newport']
            print "line 312: dstmac: ", fields['dstmac']
            print "line 313: dstip: ", fields['dstip']
            #print pkt['dstip']
            #This may no longer be necessary
            if pkt['ip'] is not None:
                actions.append(parser.OFPActionSetField(eth_dst=fields['dstmac']))
                actions.append(parser.OFPActionSetField(ipv4_dst=fields['dstip']))
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'mir':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
            mir_port = ops['newport']
            actions.append(parser.OFPActionOutput(mir_port))
        elif ops['op'] == 'craft':
            print "***\nCrafting Packet\n***"
            #create and send new pkt due to craft trigger
            self._build_pkt(fields, ops) 
            #Now drop the arrived packet
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
                                                
        return out_port, actions
    
    #More work is required here to implement active testing for NATs etc.
    # Note fields object must be completely rewritten for crafted packet
    # Probably need to make fields['ptype'] = ['arp', 'ipv4']
    def _build_pkt(self, fields, ops):
        pkt_out = packet.Packet()
        pkt_ipv4 = pkt_out.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt_out.get_protocol(icmp.icmp)

        def addIPv4(pkt_out, fields):
            pkt_out.add_protocol(ipv4.ipv4(dst=fields['dstip'],
                                version = 4,
                                header_length = 5,
                                tos = 0,
                                total_length = 0,
                                identification = fields['id'],
                                flags=0x02,
                                ttl = 63,
                                proto = fields['proto'],
                                csum = 0,
                                option = None,
                                src=fields['srcip']))
            return pkt_out

        def addARP(pkt_out,fields):
            pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=fields['srcmac'],
                                 src_ip=fields['srcip'],
                                 dst_mac=fields['dstmac'],
                                 dst_ip=fields['dstip']))
            return pkt_out

        pkt_out.add_protocol(ethernet.ethernet(ethertype=fields['ethtype'],
                                               dst=fields['dstmac'],
                                               src=fields['srcmac']))
        # Add if ARP                                           
        if 'arp' in fields['ptype']:
            pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=fields['srcmac'],
                                 src_ip=fields['srcip'],
                                 dst_mac=fields['dstmac'],
                                 dst_ip=fields['dstip']))
        # Add if IPv4
        if 'ipv4' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)
            
        # Add if ICMP
        if 'icmp' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)
            
            pkt_out.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                 code=icmp.ICMP_ECHO_REPLY_CODE,
                                 csum=0,
                                 data=None))
        # Add if UDP    
        if 'udp' in fields['ptype']:
            #pkt_out = addARP(pkt_out,fields)
            pkt_out = addIPv4(pkt_out,fields)
            pkt_out.add_protocol(udp.udp(dst_port=fields['dstport'],
                                csum = 0,
                                total_length = 0,
                                src_port=fields['srcport']))
            #	bits=fields['bits'],option=fields['opt'],
##                                            
##                                
        # Add if TCP                         	 
        if 'tcp' in fields['ptype']:
            pkt_out = addIPv4(pkt_out,fields)
            pkt_out.add_protocol(tcp.tcp(dst_port=fields['dstport'],
				bits=fields['bits'],option=fields['opt'],
                                src_port=fields['srcport']))
        #Add covert channel information                    
        if fields['com'] != None:
            pkt_out.add_protocol(fields['com'])
            
        #Send crafted packet
        print "Packet out: \n"
        print pkt_out
        self._send_packet(fields['dp'], ops['newport'], pkt_out)
	
    #Receive crafted packet and send it to the switch
    def _send_packet(self, datapath, port, pkt_out):
        if port == None: print "Port not defined" 
        #This methods sends the crafted message to the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #print pkt_out
        pkt_out.serialize()
        #self.logger.info("packet-out %s" % (pkt_out,))
        data = pkt_out.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        #print "\nout: ", out, "\n"
        datapath.send_msg(out)
		
    #Clean up and disconnect ports. Controller going down  
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def handl_port_stat(self, ev):
        switch=SimpleSwitch()
        switch.port_status_handler(ev)


## Future work needed for ryuretic. Removing flows
##    def delete_flow(self, datapath):
##        ofproto = datapath.ofproto
##        parser = datapath.ofproto_parser
##        for dst in self.mac_to_port[datapath.id].keys():
##            match = parser.OFPMatch(eth_dst=dst)
##            mod = parser.OFPFlowMod(
##                datapath, command=ofproto.OFPFC_DELETE,
##                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
##                priority=1, match=match)
##        datapath.send_msg(mod)
"""Options for mod command:
OFPFC_ADD, OFPFC_MODIFY, OFPFC_DELETE, OFPFC_DELETE_STRICT
"""

"""
http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html
in_port	Integer 32bit	Switch input port
in_phy_port	Integer 32bit	Switch physical input port
metadata	Integer 64bit	Metadata passed between tables
eth_dst	MAC address	Ethernet destination address
eth_src	MAC address	Ethernet source address
eth_type	Integer 16bit	Ethernet frame type
vlan_vid	Integer 16bit	VLAN id
vlan_pcp	Integer 8bit	VLAN priority
ip_dscp	Integer 8bit	IP DSCP (6 bits in ToS field)
ip_ecn	Integer 8bit	IP ECN (2 bits in ToS field)
ip_proto	Integer 8bit	IP protocol
ipv4_src	IPv4 address	IPv4 source address
ipv4_dst	IPv4 address	IPv4 destination address
tcp_src	Integer 16bit	TCP source port
tcp_dst	Integer 16bit	TCP destination port
udp_src	Integer 16bit	UDP source port
udp_dst	Integer 16bit	UDP destination port
sctp_src	Integer 16bit	SCTP source port
sctp_dst	Integer 16bit	SCTP destination port
icmpv4_type	Integer 8bit	ICMP type
icmpv4_code	Integer 8bit	ICMP code
arp_op	Integer 16bit	ARP opcode
arp_spa	IPv4 address	ARP source IPv4 address
arp_tpa	IPv4 address	ARP target IPv4 address
arp_sha	MAC address	ARP source hardware address
arp_tha	MAC address	ARP target hardware address
ipv6_src	IPv6 address	IPv6 source address
ipv6_dst	IPv6 address	IPv6 destination address
ipv6_flabel	Integer 32bit	IPv6 Flow Label
icmpv6_type	Integer 8bit	ICMPv6 type
icmpv6_code	Integer 8bit	ICMPv6 code
ipv6_nd_target	IPv6 address	Target address for ND
ipv6_nd_sll	MAC address	Source link-layer for ND
ipv6_nd_tll	MAC address	Target link-layer for ND
mpls_label	Integer 32bit	MPLS label
mpls_tc	Integer 8bit	MPLS TC
mpls_bos	Integer 8bit	MPLS BoS bit
pbb_isid	Integer 24bit	PBB I-SID
tunnel_id	Integer 64bit	Logical Port Metadata
ipv6_exthdr	Integer 16bit	IPv6 Extension Header pseudo-field
pbb_uca	Integer 8bit	PBB UCA header field (EXT-256 Old version of ONF Extension)
tcp_flags	Integer 16bit	TCP flags (EXT-109 ONF Extension)
actset_output	Integer 32bit	Output port from action set metadata (EXT-233 ONF Extension)
"""

"""Still need to create a method for detecting when to craft a packet.
Somehow #packets must continue to traverse the network while this occors.
Introduce a new variable perhaps, <flag> when set read to see if packet
should be crafted"""


############Obsolete code pending delete
##    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
##        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
##            return
##        pkt = packet.Packet()
##        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
##                        dst=pkt_ethernet.src,
##                        src=self.hw_addr))
##        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
##                        src=self.ip_addr,
##                        proto=pkt_ipv4.proto))
##        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
##                        code=icmp.ICMP_ECHO_REPLY_CODE,
##                        csum=0,
##                        data=pkt_icmp.data))
##        self._send_packet(datapath, port, pkt)
