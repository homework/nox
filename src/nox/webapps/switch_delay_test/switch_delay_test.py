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
from nox.lib.packet import ethernet, ipv4
from nox.coreapps.pyrt.pycomponent import CONTINUE, STOP

Switch_Delay_Test = None

EAPOL_TYPE = 0x888e
EMPTY_JSON = "{}"
TICKER = 1

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
    print ("switch %s joined"%(dpid))
    Switch_Delay_Test.st['ports'][dpid] = attrs['ports'][:]
    
def datapath_leave(dpid):
    """ Event handler for controller detection of datapath going down. """
    del  Switch_Delay_Test.st['ports'][dpid]

def handler(self):
    print "Found a packet on incoming port"
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
        return "{result:False, reason: \"No switch yet joinned\"}"
 
    for dpid in Switch_Delay_Test.st['ports'].keys():
        install_test_flows(dpid, args.get('flow_num'), args.get('flow_type'))
 
    return "{flow_num: "+args.get('flow_num')+", flow_type: "+args.get('flow_type')+", }"


def install_test_flows(dpid, num, type):

    for i in range(int(num)):
        Switch_Delay_Test.install_datapath_flow(dpid,
        { 
                core.IN_PORT: 1,
                core.DL_SRC: "11:11:11:11:11:11",
                core.DL_DST: "22:11:11:11:11:11",
                core.DL_VLAN: 65535,
                core.DL_VLAN_PCP: 0,
                core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.NW_SRC: "10.1.1.1",
                core.NW_DST: "10.1.1.2",
                core.NW_PROTO: ipv4.ipv4.UDP_PROTOCOL,
                core.NW_TOS: 0,
                core.TP_SRC: 8080,
                core.TP_DST:8080,
                },
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        [
                [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]]
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

    
    def install(self):
        Switch_Delay_Test.register_for_datapath_join(datapath_join)
        Switch_Delay_Test.register_for_datapath_leave(datapath_leave)
        self.register_handler (Packet_in_event.static_get_name(), handler)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        switch_delay_testp = webservice.WSPathStaticString("switch_delay_test")

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
