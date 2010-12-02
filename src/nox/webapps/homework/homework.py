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
from nox.netapps.dhcp.pydhcp import pydhcp_app
from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4

Homework = None

EAPOL_TYPE = 0x888e
EMPTY_JSON = "{}"
TICKER = 1

class Actions:
    """ Some useful compound actions. """
    
    really_flood = [
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]],
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_IN_PORT]],
        ]
    
    flood_and_process = [
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]],
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_NORMAL]],
        ]
    
    really_flood_and_process = [
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]],
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_IN_PORT]],
        [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_NORMAL]],
        ]

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
    Homework.post_callback(TICKER, ticker)
    return True

##
## webservice boilerplate: URL path component types
##

class WSPathIPAddress(webservice.WSPathComponent):
    """ URL IP address path component. """
    def __init__(self):
        webservice.WSPathComponent.__init__(self)

    def __str__(self): return "ipaddr"

    def extract(self, pc, data):
        if not pc:
            return webservice.WSPathExtractResult(error="End of requested URI")

        if not is_valid_ip(pc):
            return webservice.WSPathExtractResult(error="invalid IP address '%s'" % (pc,))

        return webservice.WSPathExtractResult(pc)

class WSPathEthAddress(webservice.WSPathComponent):
    """ URL Ethernet address path component. """
    def __init__(self):
        webservice.WSPathComponent.__init__(self)

    def __str__(self): return "eaddr"

    def extract(self, pc, data):
        if not pc:
            return webservice.WSPathExtractResult(error="End of requested URI")

        if not is_valid_eth(pc):
            return webservice.WSPathExtractResult(error="invalid Ethernet address '%s'" % (pc,))

        return webservice.WSPathExtractResult(pc)

##
## openflow event handlers
##
    
def datapath_join(dpid, attrs):
    """ Event handler for controller detection of live datapath (port). """
    Homework.st['ports'][dpid] = attrs['ports'][:]

    # Homework.install_datapath_flow(
    #     dpid,
    #     { core.DL_TYPE: ethernet.ethernet.ARP_TYPE, },
    #     openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
    #     Actions.flood_and_process,
    #     )
    # Homework.install_datapath_flow(
    #     dpid,
    #     { core.DL_TYPE: ethernet.ethernet.RARP_TYPE, },
    #     openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
    #     Actions.flood_and_process,
    #     )
#    Homework.install_datapath_flow(
#        dpid,
#        { core.DL_TYPE: EAPOL_TYPE, },
#        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
#        Actions.flood_and_process,
#        )

    # pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE, }
    # for eaddr, ipaddrs in Homework.st['permitted'].items():
    #     pattern[core.DL_SRC] = eaddr
    #     if not ipaddrs: 
    #         Homework.install_datapath_flow(
    #             dpid, pattern,
    #             openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
    #             Actions.really_flood,
    #             )
    
def datapath_leave(dpid):
    """ Event handler for controller detection of datapath going down. """
    del Homework.st['ports'][dpid]

##
## webservice entry points
##
    
def permit(eaddr, ipaddr=None):
    """ Permit tx/rx to/from a specified Ethernet address."""
    
    print "PERMIT", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    eaddr = util.convert_to_eaddr(eaddr)
    pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.DL_SRC: eaddr,
                }
    if not ipaddr:
        old_ipaddrs = Homework.st['permitted'].get(eaddr)
        Homework.st['permitted'][eaddr] = None

#    for dpid in Homework.st['ports']:
        ## permit the forward path to this eaddr/ipaddr
        # Homework.install_datapath_flow(
        #     dpid, pattern,
        #     openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        #     Actions.really_flood,
        #     )

        ## ...and the reverse path similarly
        # del pattern[core.DL_SRC]
        # pattern[core.DL_DST] = eaddr
        # if ipaddr:
        #     del pattern[core.NW_SRC]
        #     pattern[core.NW_DST] = ipaddr
        
        # Homework.install_datapath_flow(
        #     dpid, pattern,
        #     openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        #     Actions.really_flood,
        #     )

    return status()

def ws_permit(request, args):
    """ WS interface to permit(). """
    
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")

    ipaddr = args.get('ipaddr')
    return permit(eaddr, ipaddr)

def deny(eaddr, ipaddr):
    """ Deny tx/rx to/from a specified Ethernet address. """
                                                            
    print "DENY", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    eaddr = util.convert_to_eaddr(eaddr)
    pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.DL_SRC: eaddr,
                }
    for dpid in Homework.st['ports']:
        #Homework.delete_strict_datapath_flow(dpid, pattern)
        ## ...and the reverse path similarly
        del pattern[core.DL_SRC]
        pattern[core.DL_DST] = eaddr
        #Homework.delete_strict_datapath_flow(dpid, pattern)
    if eaddr in Homework.st['permitted']:
        del Homework.st['permitted'][eaddr]
    data = Homework._dhcp.revoke_mac_addr(eaddr)
    return status()

def ws_deny(request, args):
    """ WS interface to deny(). """
                                   
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    ipaddr = args.get('ipaddr')

    return deny(eaddr, ipaddr)

def status(eaddr=None):
    """ Permit/Deny status of specified/all addresses. """

    if not eaddr:
        permitted = { "permitted": list(map(str, Homework.st['permitted'].keys())), }
    else:
        eaddr = util.convert_to_eaddr(eaddr)
        result = "permitted" if eaddr in permitted else "denied"
    return json.dumps(permitted)


def ws_status(request, args):
    """ WS interface to status(). """
    eaddr = args.get("eaddr")
    return status(eaddr)

def ws_dhcp_status(request, args):
    """ Get a copy of the current assignment of ip addresses to mac addresses. """
    data = Homework._dhcp.get_dhcp_mapping()
    return json.dumps(data)  

##
## main
##

class homework(core.Component):
    """ Main application. """
    
    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global Homework
        Homework = self
        Homework.st = { 'permitted': {}, ## eaddr -> None ## [ipaddr, ...]
                        'ports': {},     ## dpid -> attrs
                        }
    
    def permit_ether_addr(self, eaddr):
        if not self.st:
            print "some object is not initialized yet"
            return False
        else:
            eaddr = util.convert_to_eaddr(eaddr)
            return (eaddr in self.st['permitted'].keys())


    def hello_world(self):
        return "Hello World!!!"
    
    def install(self):
        Homework.register_for_datapath_join(datapath_join)
        Homework.register_for_datapath_leave(datapath_leave)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        self._dhcp = self.resolve(pydhcp_app)
        print self._dhcp.get_dhcp_mapping()
        self._dhcp.register_object(self)


        homeworkp = webservice.WSPathStaticString("homework")

        permitp = webservice.WSPathStaticString("permit")
        permit_eth_path = (homeworkp, permitp, WSPathEthAddress(),)
        v1.register_request(ws_permit, "POST", permit_eth_path, """Permit an Ethernet address.""")
##         permit_ip_path = (homeworkp, permitp, WSPathEthAddress(), WSPathIPAddress(),)
##         v1.register_request(ws_permit, "POST", permit_ip_path, """Permit an IP address.""")

        denyp = webservice.WSPathStaticString("deny")
        deny_eth_path = (homeworkp, denyp, WSPathEthAddress(),)
        v1.register_request(ws_deny, "POST", deny_eth_path, """Deny an Ethernet address.""")
##         deny_ip_path = (homeworkp, denyp, WSPathEthAddress(), WSPathIPAddress(),)
##         v1.register_request(ws_deny, "POST", deny_ip_path, """Deny an IP address.""")

        statusp = webservice.WSPathStaticString("status")
        status_path = (homeworkp, statusp,)
        v1.register_request(ws_status, "GET", status_path, """Status of all Ethernet addresses.""")
        status_eth_path = (homeworkp, statusp, WSPathEthAddress(),)
        v1.register_request(ws_status, "GET", status_eth_path, """Status of an Ethernet address.""")

        dhcpp = webservice.WSPathStaticString("dhcp_status")
        dhcp_status_path = (homeworkp, dhcpp,)
        v1.register_request(ws_dhcp_status, "GET", dhcp_status_path, """Status of dhcp assignments.""")
        
    def getInterface(self): return str(homework)

def getFactory():
    class Factory:
        def instance(self, ctxt): return homework(ctxt)
    return Factory()
