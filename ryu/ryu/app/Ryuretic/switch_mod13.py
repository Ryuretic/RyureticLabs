########################################################
# Author Jacob Cox
# switch_mod.py
# Date 1 February 2016
######################################################3
"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
#from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def handle_pkt(self,pkt):
        #print "*********pkt_in_handler - SimpleSwitch********"
        msg, datapath, ofproto = pkt['msg'], pkt['dp'], pkt['ofproto']
        eth = pkt['pkt'].get_protocols(ethernet.ethernet)[0]
        dst, src = eth.dst, eth.src
        dpid = datapath.id
        #self.logger.info("packet in %s %s %s %s", dpid%100, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time (tablemaps ports to mac per dp)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = pkt['inport']

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        return out_port


    #Called by coupler to add or delete port connection.
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
