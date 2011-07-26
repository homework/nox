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

from nox.webapps.webservice import webservice
from nox.coreapps.pyrt.pycomponent import Packet_in_event 
from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4, packet_utils
from nox.coreapps.pyrt.pycomponent import CONTINUE, STOP

Switch_Delay_Test = None

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

class WSPathExactNum(webservice.WSPathComponent):
    def __init__(self):
        webservice.WSPathComponent.__init__(self)
    def __str__(self):
        return "exact_num"
    def extract(self, pc, data):
        # check this is number
        return webservice.WSPathExtractResult(pc)

class WSPathWildNum(webservice.WSPathComponent):
    def __init__(self):
        webservice.WSPathComponent.__init__(self)
    def __str__(self):
        return "wild_num"
    def extract(self, pc, data):
        # check this is number
        return webservice.WSPathExtractResult(pc)

##
## openflow event handlers
##
    
def datapath_join(dpid, attrs):
    """ Event handler for controller detection of live datapath (port). """
    print ("switch %s joined"%(dpid))
    Switch_Delay_Test.st['ports'][dpid] = attrs['ports'][:]
    
def datapath_leave(dpid):
    """ Event handler for controller detection of datapath going down. """
    del  Switch_Delay_Test.st['ports'][dpid]

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
    if len(Switch_Delay_Test.st['ports']) < 1 :
        return "{\"result\":0, \"reason\": \"No switch yet joinned\"}"
 
    for dpid in Switch_Delay_Test.st['ports'].keys():
        if not install_test_flows(dpid, args.get('flow_num'), args.get('flow_type')) :
            return "{\"result\":0, \"reason\": \"Invalid params\"}"

    return "{\"result\":1}"


def ws_reset_flows(request, args):
    """ WS interface to permit(). """
    print args  

    if len(Switch_Delay_Test.st['ports']) < 1 :
        return "{\"result\":0, \"reason\": \"No switch yet joinned\"}"
    print "delete flows"

    for dpid in Switch_Delay_Test.st['ports'].keys():
        Switch_Delay_Test.delete_datapath_flow(dpid, {})

    return "{\"result\":1}" 


def ws_mix_flows(request, args):
    """ WS interface to permit(). """
    print args  
    if len(Switch_Delay_Test.st['ports']) < 1 :
        return "{\"result\":0, \"reason\": \"No switch yet joinned\"}"

    print "insert mix flows"
    for dpid in Switch_Delay_Test.st['ports'].keys():
        print ("%s %s"%(args.get('wild_num'), args.get('exact_num')));
        install_mix_flows(dpid, args.get('wild_num'), args.get('exact_num'))

    return "{\"result\":1}" 

def install_mix_flows(dpid, wild, exact):
    j=1
#    wild= 0
    for i in range(int(exact)):
        dst_ip = ("10.3.%d.%d"%(int((i/256)),i%256))        
        print dst_ip
        Switch_Delay_Test.install_datapath_flow(dpid,
        { 
                core.IN_PORT: 1,
                core.DL_SRC: "10:20:30:40:50:61",
                core.DL_DST: "10:20:30:40:50:60",
                core.DL_VLAN: 0xffff,
                core.DL_VLAN_PCP: 0,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_SRC: "10.2.0.1",
                core.NW_DST: dst_ip,
                core.NW_DST_N_WILD: 0,
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_SRC: 8080,
                core.TP_DST:8080,
                }, 
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        [
                [openflow.OFPAT_SET_DL_SRC, "10:20:30:40:50:60"],
                [openflow.OFPAT_SET_DL_DST, "10:20:30:40:50:62"],
                [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_IN_PORT]]
         ],
        )

    i = (i)/256
    for j in range(int(wild)):
        i=i+1
        dst_ip = ("10.%d.%d.0"%(int((i/256)),i%256))        
        print dst_ip
        Switch_Delay_Test.install_datapath_flow(dpid,
        { 
                core.IN_PORT: 1,
                core.DL_SRC: "10:20:30:40:50:61",
                core.DL_DST: "10:20:30:40:50:60",
                core.DL_VLAN: 0xffff,
                core.DL_VLAN_PCP: 0,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_SRC: "10.2.0.1",
                core.NW_DST: dst_ip,
                core.NW_DST_N_WILD: 8,
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_SRC: 8080,
                core.TP_DST:8080,
                }, 
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        [
                [openflow.OFPAT_SET_DL_SRC, "10:20:30:40:50:60"],
                [openflow.OFPAT_SET_DL_DST, "10:20:30:40:50:62"],
                [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_IN_PORT]]
         ],
        )


    return True

#
#  curl -i -k -X POST -H "Content-Type: application/json" -d "{\"hello\":\"world\"}" \
#  https://10.1.0.1/ws.v1/switch_delay_test/test_http_body
#    
def install_test_flows(dpid, num, type):
    j=1
    wild= 0
    for i in range(int(num)):
        i=i+1
        if(type == "exact") :
            dst_ip = ("10.3.%d.%d"%(int((i/256)),i%256))
            wild = 0
        elif (type == "wildcard"):
            dst_ip = ("10.%d.%d.0"%(int((i/256) + 3),i%256))
            wild = 8
        else :
            print "Invalid type"
            return False

        print dst_ip
        Switch_Delay_Test.install_datapath_flow(dpid,
        { 
                core.IN_PORT: 1,
                core.DL_SRC: "10:20:30:40:50:61",
                core.DL_DST: "10:20:30:40:50:60",
                core.DL_VLAN: 0xffff,
                core.DL_VLAN_PCP: 0,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_SRC: "10.2.0.1",
                core.NW_DST: dst_ip,
                core.NW_DST_N_WILD: wild,
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_SRC: 8080,
                core.TP_DST:8080,
                }, 
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        [
                [openflow.OFPAT_SET_DL_SRC, "10:20:30:40:50:60"],
                [openflow.OFPAT_SET_DL_DST, "10:20:30:40:50:62"],
                [openflow.OFPAT_OUTPUT, [-1,  openflow.OFPP_IN_PORT]]
         ],
        )

    return True

##
## main
##
class switch_delay_test(core.Component):
    """ Main application. """
    
    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global  Switch_Delay_Test
        Switch_Delay_Test = self
        self.st = {}
        self.st['ports']={}


    def pkt_in_handler(self, dp_id, inport, ofp_reason, total_frame_len, buffer_id, packet):
        attrs = util.extract_flow(packet)
        print "Pakcet in received "+str(inport)+ " " +packet_utils.ip_to_str(attrs['nw_dst'])
        # print attrs

        # print ("type:%s %s > %s  %s:%d > %s:%d "%(
        #         packet_utils.ethtype_to_str(attrs['dl_type']),
        #         packet_utils.mac_to_str(attrs['dl_src']),
        #         packet_utils.mac_to_str(attrs['dl_dst']),
        #         packet_utils.ip_to_str(attrs['nw_src']), attrs['tp_src'],
        #         packet_utils.ip_to_str(attrs['nw_dst']), attrs['tp_dst']
        #         ))
        return CONTINUE
        
    
    def install(self):
        match = {core.DL_TYPE: ethernet.ethernet.IP_TYPE}

        Switch_Delay_Test.register_for_datapath_join(datapath_join)
        Switch_Delay_Test.register_for_datapath_leave(datapath_leave)
        self.register_for_packet_match(lambda
            dp,inport,reason,len,bid,packet :
            switch_delay_test.pkt_in_handler(self,dp,inport,reason,len,bid,packet),
            0xffff, match)
        #self.register_handler (Packet_in_event.static_get_name(), handler)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        switch_delay_testp = webservice.WSPathStaticString("switch_delay_test")

        permitp = webservice.WSPathStaticString("resetflows")
        resetflows = ( switch_delay_testp, permitp)
        v1.register_request(ws_reset_flows, "GET", resetflows, 
                            "Send details about the installed flows for the test.")

        permitp = webservice.WSPathStaticString("mixflows")
        exactp = webservice.WSPathStaticString("exact")
        wildp = webservice.WSPathStaticString("wild")
        mixflows = ( switch_delay_testp,permitp, exactp, WSPathExactNum(),wildp, WSPathWildNum())
        v1.register_request(ws_mix_flows, "GET", mixflows, 
                            "Send details about the installed flows for the test.")

        permitp = webservice.WSPathStaticString("installflows")
        installflows = ( switch_delay_testp, permitp, 
                         WSPathFlowNum(), WSPathFlowType())
        v1.register_request(ws_install_flows, "GET", installflows, 
                            "Send details about the installed flows for the test.")
        
    def getInterface(self): return str( switch_delay_test)

def getFactory():
    class Factory:
        def instance(self, ctxt): return  switch_delay_test(ctxt)
    return Factory()
