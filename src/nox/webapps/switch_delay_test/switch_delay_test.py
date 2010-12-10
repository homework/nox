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
from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4

 Switch_Delay_Test = None

EAPOL_TYPE = 0x888e
EMPTY_JSON = "{}"
TICKER = 1

##
## utility functions
##
    
def invert_flow(flow):
    """ Swap source and destination L2 and L3 addresses. """
    s, d = flow['dl_src'], flow['dl_dst']
    flow['dl_src'], flow['dl_dst'] = d, s

    s, d = flow['nw_src'], flow['nw_dst']
    flow['nw_src'], flow['nw_dst'] = d, s
    
    return flow

def is_valid_ip(ip):
    """ Test if string is valid representation of IP address. """
    quads = ip.split(".")
    if len(quads) != 4: return False

    try: return reduce(lambda acc,quad: (0 <= quad <= 255) and acc, map(int, quads), True)
    except ValueError: return False

def is_valid_eth(eth):
    """ Test if string is valid representation of Ethernet address. """
    if ":" in eth: bytes = eth.split(":")
    elif "-" in eth: bytes = eth.split("-")
    else: return False ## else: bytes = [ eth[i:i+2] for i in range(0,len(eth),2) ]

    if len(bytes) != 6: return False    

    try: return reduce(lambda acc,byte: (0 <= byte <= 256) and acc,
                       map(lambda b: int(b,16), bytes), True)
    except ValueError: return False

def ticker():
    """ Placeholder ticker callback. """
    now = time.time()
    print "TICK", now
     Switch_Delay_Test.post_callback(TICKER, ticker)
    return True

##
## openflow event handlers
##
    
def datapath_join(dpid, attrs):
    """ Event handler for controller detection of live datapath (port). """
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
# curl -i -X POST -d 'json={"flow_num":10, "type":"wildcard", "wildcard":0}'  \
#      http://localhost/ switch_delay_test/installflows
#
def ws_install_flows(request, args):
    """ WS interface to permit(). """
    print args
    
    return "{result: success}"


##
## main
##
class switch_delay_test(core.Component):
    """ Main application. """
    
    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global  Switch_Delay_Test
         Switch_Delay_Test = self

    
    def install(self):
        Switch_Delay_Test.register_for_datapath_join(datapath_join)
        Switch_Delay_Test.register_for_datapath_leave(datapath_leave)
        self.register_handler (Packet_in_event.static_get_name(), handler)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        switch_delay_testp = webservice.WSPathStaticString("switch_delay_test")

        permitp = webservice.WSPathStaticString("installflows")
        installflows = ( switch_delay_testp, permitp, WSPathEthAddress(),)
        v1.register_request(ws_install_flows, "POST", installflows, 
                            "Send details about the installed flows for the test.")
        
    def getInterface(self): return str( switch_delay_test)

def getFactory():
    class Factory:
        def instance(self, ctxt): return  switch_delay_test(ctxt)
    return Factory()
