## Copyright (C) 2010 Richard Mortier <mort@cantab.net>.
## All Rights Reserved.
##
## This program is free software: you can redistribute it and/or
## modify it under the terms of the GNU Affero General Public License
## as published by the Free Software Foundation, either version 3 of
## the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public
## License along with this program.  If not, see
## <http://www.gnu.org/licenses/>.
    
import pprint, time, re
ppf = pprint.pprint
import simplejson as json

import os
import sys
import re
from nox.webapps.webservice import webservice
from nox.coreapps.pyrt.pycomponent import Packet_in_event 
from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4, packet_utils
from nox.coreapps.pyrt.pycomponent import CONTINUE, STOP

test = None

##
## utility functions
##

class WSPathFlowNum(webservice.WSPathComponent):
    def __init__(self):
        webservice.WSPathComponent.__init__(self)
        #self.userdb = userdb   # Keep ref to userdb for later use

    def __str__(self):
        return "flow_num"

    def extract(self, pc, data):
        # check this is number
        return webservice.WSPathExtractResult(pc)

class WSPathFlowType(webservice.WSPathComponent):
    def __init__(self):
        webservice.WSPathComponent.__init__(self)
        #self.userdb = userdb   # Keep ref to userdb for later use

    def __str__(self):
        return "flow_type"

    def extract(self, pc, data):
        # allow only a couple of values and check
        return webservice.WSPathExtractResult(pc)

##
## openflow event handlers
##
def datapath_join(dpid, attrs):
    """ Event handler for controller detection of live datapath (port). """
    test.install_datapath_flow(dpid,
                               {
            core.DL_TYPE: ethernet.ethernet.IP_TYPE,
            core.NW_DST: "10.2.0.1",
            core.NW_PROTO: ipv4.ipv4.TCP_PROTOCOL,
            core.TP_DST: 443,
            },openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                               [
            [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_LOCAL]]
            ],)
    test.install_datapath_flow(dpid,
                               {
            core.DL_TYPE: ethernet.ethernet.IP_TYPE,
            core.NW_SRC: "10.2.0.1",
            core.NW_PROTO: ipv4.ipv4.TCP_PROTOCOL,
            core.TP_SRC: 443,
            },openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                               [
            [openflow.OFPAT_OUTPUT, [-1, 1]]
            ],)
    test.install_datapath_flow(dpid,
                               {
            core.DL_TYPE: ethernet.ethernet.ARP_TYPE,
            },openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                               [
            [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_FLOOD]],
            [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_LOCAL]],
            [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_IN_PORT]]
            ],)

    test.install_datapath_flow(dpid, { 
            core.IN_PORT: 1,
            core.DL_TYPE: ethernet.ethernet.IP_TYPE,
            core.NW_DST: "10.3.0.0",
            core.NW_DST_N_WILD: 16,
            }, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                               [
            [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_LOCAL]]
            ],)

    test.install_datapath_flow(dpid, { 
            core.IN_PORT: 0,
            core.DL_TYPE: ethernet.ethernet.IP_TYPE,
            core.NW_SRC: "10.3.0.0",
            core.NW_SRC_N_WILD: 16,
            }, openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                               [
            [openflow.OFPAT_OUTPUT, [-1, 1]]
            ],)
    print ("switch %s joined"%(dpid))
    test.st['ports'][dpid] = attrs['ports'][:]
    os.system("ip addr add 10.2.0.1/30 dev br0")
    
def datapath_leave(dpid):
    """ Event handler for controller detection of datapath going down. """
    del  test.st['ports'][dpid]

def handler(pkt_in):
    print "Found a packet on incoming port "+str(pkt_in)
    return  CONTINUE

##
## Managment of web service 
##              
#
#  curl -k -X GET https://localhost/ws.v1/switch_delay_test/installflows/10/wildcard
#
def ws_install_flows(request, args):
    """ WS interface to permit(). """
    print args  
    if len(test.st['ports']) < 1 :
        return "{\"result\":0, \"reason\": \"No switch yet joinned\"}"
 
    for dpid in test.st['ports'].keys():
        if not install_test_flows(dpid, args.get('flow_num')) :
            return "{\"result\":0, \"reason\": \"Invalid params\"}"

    return "{\"result\":1}"
    
def install_test_flows(dpid, num):
    j=1
    wild= 0
    for i in range(int(num)):
        i=i+1
        nw_src_host = ("10.2.%d.%d"%(int(i/64),((int(i%64)<<2)+2)))
        nw_src_router = ("10.2.%d.%d"%(int(i/64),(int(i%64)<<2)+1))
        dl_src = ("10:20:30:40:%x:%x"%(int((i/256)),i%256))

        # install flows to forward packets to bridge and back in order to do 
        # the natting.
        print  nw_src_host + " " + nw_src_router
        test.install_datapath_flow(dpid,{ 
                core.IN_PORT: 1,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_DST: "10.3.0.0",
                core.NW_DST_N_WILD: 16,
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_DST:7,
                },openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                                   [
                [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_LOCAL]]
                ],)

        test.install_datapath_flow(dpid,{ 
                core.IN_PORT: 0,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_SRC: "10.3.0.0",
                core.NW_SRC_N_WILD: 16,
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_SRC: 7,
                },openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                                   [
                [openflow.OFPAT_OUTPUT, [-1,  1]]
                ],)
        os.system(("ip addr add %s/30 dev br0"%(nw_src_router)));
    return True
    
##
## main
##
class network_stack_test(core.Component):
    """ Main application. """
    
    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global  test
        test = self
        self.st = {}
        self.st['ports']={}
        self. bridge_mac = ""

    def pkt_in_handler(self, dp_id, inport, ofp_reason, total_frame_len, buffer_id, packet):
        attrs = util.extract_flow(packet)
        print "Pakcet in received "+str(inport)+ " " +packet_utils.ip_to_str(attrs['nw_dst'])
        return CONTINUE
        
    
    def install(self):
        res = os.popen("ifconfig br0")
        if res == None:
            sys.exit(1)
        for line in res.readlines():
            if re.search("HWaddr (([\da-fA-F]{2}[\:]{0,1}){6})", line) != None:
                self.bridge_mac = re.search("HWaddr (([\da-fA-F]{2}[\:]{0,1}){6})", line).group(1)
        if self.bridge_mac == "":
            print "Failed to find bridge interface"
            sys.exit(1)
        else:
            print "bridge mac: "+self.bridge_mac

        #
        #clean up the br0 assigned ips
        #
        res = os.popen("ip addr show dev br0")
        if res == None:
            sys.exit(1)
        
        for line in res.readlines():
            if re.search("inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line) != None:
                ip = re.search("inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", line).group(1)
                print "removing ip " + ip + " from dev br0 "
                os.system(("ip addr del %s dev br0"%(ip)));
            
        match = {core.DL_TYPE: ethernet.ethernet.IP_TYPE}

        self.register_for_datapath_join(datapath_join)
        self.register_for_datapath_leave(datapath_leave)
        self.register_for_packet_match(lambda
            dp,inport,reason,len,bid,packet :
            network_stack_test.pkt_in_handler(self,dp,inport,reason,len,bid,packet),
            0xffff, match)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        switch_delay_testp = webservice.WSPathStaticString("network_stack_test")
        permitp = webservice.WSPathStaticString("installflows")
        installflows = ( switch_delay_testp, permitp, WSPathFlowNum())
        v1.register_request(ws_install_flows, "GET", installflows, 
                            "Send details about the installed flows for the test.")
        
    def getInterface(self): return str(test)

def getFactory():
    class Factory:
        def instance(self, ctxt): return  network_stack_test(ctxt)
    return Factory()
