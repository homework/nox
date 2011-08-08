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
from nox.netapps.homework_routing.pydhcp import pydhcp_app
from nox.netapps.hwdb.pyhwdb import pyhwdb

from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4

import os

Homework = None

EMPTY_JSON = "{}"
TICKER = 1


##
## utility functions
##

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
    Homework.st['permitted'][eaddr] = True
    Homework._hwdb.insert("SQL:insert into Devices values (\"%s\", \"permit\")"%(eaddr))
    return status()

def ws_permit(request, args):
    """ WS interface to permit(). """
    
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")

    ipaddr = args.get('ipaddr')
    return permit(eaddr, ipaddr)
#
# curl -i -k -X POST -H "Content-Type: application/json" \
# -d "[\"11:11:11:11:11:11\",\"22:22:22:22:22:22\"]" \
# https://10.1.0.1/ws.v1/homework/permit_group
#
def ws_permit_group(request, args):
    """ WS interface to permit(). """
    content = webservice.json_parse_message_body(request)
    if content == None:
        print "error in getting state"
        return  webservice.badRequest(request, "missing eaddr")
    for eaddr in content:
        if not is_valid_eth(eaddr):
            return   webservice.badRequest(request, "malformed eaddr " + eaddr)
    for eaddr in content:
        permit(eaddr)
    return status()

def deny(eaddr, ipaddr = None):
    """ Deny tx/rx to/from a specified Ethernet address. """
    print "DENY", eaddr, ipaddr
    if not (eaddr or ipaddr): return
    eaddr = util.convert_to_eaddr(eaddr)
    del Homework.st['permitted'][eaddr]
    Homework._hwdb.insert("SQL:insert into Devices values (\"%s\", \"deny\")"%(eaddr))
    #data = Homework._dhcp.revoke_mac_addr(eaddr)
    return status()

def ws_deny(request, args):
    """ WS interface to deny(). """
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    ipaddr = args.get('ipaddr')
    return deny(eaddr, ipaddr)

#
# curl -i -k -X POST -H "Content-Type: application/json" \
# -d "[\"11:11:11:11:11:11\",\"22:22:22:22:22:22\"]" \
# https://10.1.0.1/ws.v1/homework/permit_group
#
def ws_deny_group(request, args):
    """ WS interface to permit(). """
    content = webservice.json_parse_message_body(request)
    if content == None:
        print "error in getting state"
        return  webservice.badRequest(request, "missing eaddr")

    for eaddr in content:
        if not is_valid_eth(eaddr):
            return   webservice.badRequest(request, "malformed eaddr " + eaddr)

    for eaddr in content:
        deny(eaddr)
    return status()

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

def ws_whitelist_eth(request, args):
    """ Remove a mac address from filtering eap traffic. """
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    eaddr = util.convert_to_eaddr(eaddr)
    Homework._hwdb.insert("SQL:insert into Devices values (\"%s\", \"deny\")"%(eaddr))
    return json.dumps(Homework._dhcp.get_blacklist_mac_status())

def ws_blacklist_eth(request, args):
    """ Aggressive mac address exclusion at the level of wpa connectivity. """
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    eaddr = util.convert_to_eaddr(eaddr)
    if eaddr in Homework.st['permitted']:
        del Homework.st['permitted'][eaddr]
#        Homework._dhcp.revoke_mac_addr(eaddr)
    Homework._hwdb.insert("SQL:insert into Devices values (\"%s\", \"blacklist\")"%(eaddr))
    return json.dumps(Homework._dhcp.get_blacklist_mac_status())


def ws_blacklist_status(request, args):
    """ get a list of mac addresses in the blacklist list. """
    return  json.dumps(Homework._dhcp.get_blacklist_mac_status())

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
        if os.path.exists("/etc/homework/whitelist.conf") : 
            permit_list = open("/etc/homework/whitelist.conf", "r")

            for eaddr in permit_list:
                eaddr = eaddr.strip()
                print "PERMIT", eaddr
                eaddr = util.convert_to_eaddr(eaddr)
                self.st['permitted'][eaddr] = None
    
    def install(self):
        Homework.register_for_datapath_join(datapath_join)
        Homework.register_for_datapath_leave(datapath_leave)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        self._dhcp = self.resolve(pydhcp_app)
        print self._dhcp.get_dhcp_mapping()
        self._dhcp.register_object(self)
        
        # gettting a reference for the hwdb component
        self._hwdb = self.resolve(pyhwdb)
        # print "hwdb obj " + str(self._hwdb)

        homeworkp = webservice.WSPathStaticString("homework")

        permitp = webservice.WSPathStaticString("permit")
        permit_eth_path = (homeworkp, permitp, WSPathEthAddress(),)
        v1.register_request(ws_permit, "POST", permit_eth_path, """Permit an Ethernet address.""")

        permit_groupp = webservice.WSPathStaticString("permit_group")
        permit_group_eth_path = (homeworkp, permit_groupp)
        v1.register_request(ws_permit_group, "POST", permit_group_eth_path, """Permit a set of  Ethernet addresses 
represented as json array in the body of the http post.""")

        denyp = webservice.WSPathStaticString("deny")
        deny_eth_path = (homeworkp, denyp, WSPathEthAddress(),)
        v1.register_request(ws_deny, "POST", deny_eth_path, """Deny an Ethernet address.""")

        deny_groupp = webservice.WSPathStaticString("deny_group")
        deny_group_eth_path = (homeworkp, deny_groupp)
        v1.register_request(ws_deny_group, "POST", deny_group_eth_path, """Deny access to a set of  Ethernet addresses 
represented as json array in the body of the http post.""")

        statusp = webservice.WSPathStaticString("status")
        status_path = (homeworkp, statusp,)
        v1.register_request(ws_status, "GET", status_path, """Status of all Ethernet addresses.""")
        status_eth_path = (homeworkp, statusp, WSPathEthAddress(),)
        v1.register_request(ws_status, "GET", status_eth_path, """Status of an Ethernet address.""")

        dhcpp = webservice.WSPathStaticString("dhcp_status")
        dhcp_status_path = (homeworkp, dhcpp,)
        v1.register_request(ws_dhcp_status, "GET", dhcp_status_path, """Status of dhcp assignments.""")

        dhcpp = webservice.WSPathStaticString("blacklist")
        blacklist_eth_path = (homeworkp, dhcpp, WSPathEthAddress(),)
        v1.register_request(ws_blacklist_eth, "GET", blacklist_eth_path, """Forbid a mac address from connecting on the wpa level.""")
        dhcpp = webservice.WSPathStaticString("whitelist")
        whitelist_eth_path = (homeworkp, dhcpp, WSPathEthAddress(),)
        v1.register_request(ws_whitelist_eth, "GET", whitelist_eth_path, """Allow a mac address to connect at the wpa level.""")
        dhcpp = webservice.WSPathStaticString("blacklist_status")
        blacklist_status_path = (homeworkp, dhcpp, )
        v1.register_request(ws_blacklist_status, "GET", blacklist_status_path, """List of blacklisted mac addresses.""")
        
    def getInterface(self): return str(homework)

def getFactory():
    class Factory:
        def instance(self, ctxt): return homework(ctxt)
    return Factory()
