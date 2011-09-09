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
from nox.lib.packet import ethernet, ipv4, dns
from nox.coreapps.pyrt.pycomponent import CONTINUE, STOP

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

def is_valid_hostname(hostname):
    """ Test if string is valid representation of a hostname name. """
    if len(hostname) > 255:
	return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

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

class WSPathHostName(webservice.WSPathComponent):
    """ URL hostname path component. """
    def __init__(self):
        webservice.WSPathComponent.__init__(self)

    def __str__(self): return "hostname"

    def extract(self, pc, data):
        if not pc:
            return webservice.WSPathExtractResult(error="End of requested URI")

        if not is_valid_hostname(pc):
            return webservice.WSPathExtractResult(error="invalid hostname name '%s'" % (pc,))

        return webservice.WSPathExtractResult(pc)


##
## openflow event handlers
##
    
def datapath_join(dpid, attrs):
    """ Event handler for controller detection of live datapath (port). """
    print "Datapath join"
    print dpid
    print attrs
    Homework.st['ports'][dpid] = attrs['ports'][:]

    Homework.install_datapath_flow(dpid, 
                                   { core.DL_TYPE : ethernet.ethernet.IP_TYPE,
                                     core.NW_PROTO : ipv4.ipv4.UDP_PROTOCOL,
                                     core.TP_DST : 53 }, 
                                   openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
#			           Actions.really_flood_and_process,)
                                   [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_CONTROLLER]]], None, 0xFFFF)

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
    

def dns_permit(eaddr, hostname):

    print "DNS PERMIT", eaddr, hostname
    if not (eaddr and hostname): return 
    
    eaddr = util.convert_to_eaddr(eaddr)

    Homework.st['dnsList'][eaddr].discard(hostname)
    
    return status()    
    
def permit(eaddr, ipaddr=None):
    """ Permit tx/rx to/from a specified Ethernet address."""
    
    print "PERMIT", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    ## TODO Add rule to forward dns requests
    
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

def ws_dns_deny(request, args):
    """ WS interface to dns_deny(). """

    print request
    print args

    eaddr = args.get('eaddr')
    hostname = args.get('hostname')
    if not (eaddr and hostname): return webservice.badRequest(request, "missing eaddr")
      
    return dns_deny(eaddr, hostname)

def ws_dns_permit(request, args):
    """ WS interface to dns_permit(). """

    print request
    print args

    eaddr = args.get('eaddr')
    hostname = args.get('hostname')
    if not (eaddr and hostname): return webservice.badRequest(request, "missing eaddr")
      
    return dns_permit(eaddr, hostname)

#
# curl -i -k -X POST -H "Content-Type: application/json" \
# -d "[\"11:11:11:11:11:11\",\"22:22:22:22:22:22\"]" \
# https://10.1.0.1/ws.v1/homework/permit_group
#
def ws_dns_permit_group(request, args):
    """ WS interface to dns_permit(). """

    print request
    print args

    content = webservice.json_parse_message_body(request)
    if content == None:
        print "error in getting state"
        return  webservice.badRequest(request, "missing eaddr")

    for permititem in content:
        if not is_valid_eth(permititem['eaddr']):
            return   webservice.badRequest(request, "malformed eaddr " + eaddr)

    for permititem in content:
        dns_permit(permititem['eaddr'], permititem['hostname'])
        
    return status()
        
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

#    eaddr = args.get('eaddr')
#    if not eaddr: return webservice.badRequest(request, "missing eaddr")

    return '{"status" : "success"}' #permit(eaddr)

def dns_deny(eaddr, hostname):
    """ Deny tx/rx to/from a specified Ethernet address. """
                                                            
    print "DENY", eaddr, hostname
    if not (eaddr and hostname): return 
    
    eaddr = util.convert_to_eaddr(eaddr)

    if eaddr not in Homework.st['dnsList']:
        Homework.st['dnsList'][eaddr] = set([hostname])
    else:
        Homework.st['dnsList'][eaddr].add(hostname)

    print Homework.st

    return status()


def deny(eaddr, ipaddr = None):
    """ Deny tx/rx to/from a specified Ethernet address. """
                                                            
    print "DENY", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    eaddr = util.convert_to_eaddr(eaddr)
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

def ws_dns_deny_group(request, args):
    """ WS interface to dns_deny_group(). """
    
    print request
    print args

    content = webservice.json_parse_message_body(request)
    if content == None:
        print "error in getting state"
        return  webservice.badRequest(request, "missing eaddr")

    for permititem in content:
        if not is_valid_eth(permititem['eaddr']):
            return   webservice.badRequest(request, "malformed eaddr " + eaddr)

    for permititem in content:
        dns_deny(permititem['eaddr'], permititem['hostname'])

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
        dnsList = dict()
        for key in Homework.st['dnsList']:
            dnsList[str(key)] = list(Homework.st['dnsList'][key])
        permitted = { "permitted": list(map(str, Homework.st['permitted'].keys())), "dnsList": dnsList, }
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
    data = Homework._dhcp.whitelist_mac_addr(eaddr)
    return json.dumps(Homework._dhcp.get_blacklist_mac_status())

def ws_blacklist_eth(request, args):
    """ Aggressive mac address exclusion at the level of wpa connectivity. """
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    eaddr = util.convert_to_eaddr(eaddr)
    if eaddr in Homework.st['permitted']:
        del Homework.st['permitted'][eaddr]
        Homework._dhcp.revoke_mac_addr(eaddr)
    Homework._dhcp.blacklist_mac_addr(eaddr)
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
                        'domains': {},   ## domain -> ip
                        'dnsList': {},   ## eaddr -> domains
##                      'devices': {}    ## eaddr -> devices {permitted: bool, domains: set}
                        }
    
    def permit_ether_addr(self, eaddr):
        if not self.st:
            print "some object is not initialized yet"
            return False
        else:
            eaddr = util.convert_to_eaddr(eaddr)
            return (eaddr in self.st['permitted'].keys())


    def permit_dns(self, eaddr, hostname):
        if not self.st:
            print "some object is not initialized yet"
            return False
        else:
            eaddr = util.convert_to_eaddr(eaddr)
            return (eaddr in self.st['dnsList'].keys() and hostname in self.st['dnsList'][eaddr].keys())
        

    def hello_world(self):
        return "Hello World!!!"

    def handle_dns_response(self, dpid, inport, ofp_reason, total_frame_len, buffer_id, packet):
        eaddr = util.convert_to_eaddr(packet.dst)
        dnsh = packet.find('dns')

        if not self.permit_ether_addr(eaddr):
            print "Dropping DNS Response Packet - MAC Address not allowed"
            return STOP

        if not dnsh:
            print "\n\n +++ +++ Invalid DNS Response packet: ", dnsh
            print packet
            print dir(packet)
            print packet.__dict__
            print "\n\n"
            return CONTINUE

        print "DNS Response packet:", dnsh

        print "*******", dir(dnsh)
        print "*******", dnsh.__dict__

        for answer in dnsh.answers:
            if answer.qtype in dns.rrtype_to_str:
                domain = answer.name + ":" + dns.rrtype_to_str[answer.qtype]
            else:
                domain = answer.name + ":" + str(answer.qtype)

            if domain not in Homework.st['domains']:
                Homework.st['domains'][domain] = set([str(answer.rddata)])
            else:
                Homework.st['domains'][domain].add(str(answer.rddata))

        flow = util.extract_flow(packet)
        Homework.install_datapath_flow(
             dpid, flow, 3, 10,
             [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_NORMAL]]],
             buffer_id, openflow.OFP_DEFAULT_PRIORITY, inport, dnsh.arr
             )

        return CONTINUE

    
    def handle_dns(self, dpid, inport, ofp_reason, total_frame_len, buffer_id, packet):
        eaddr = util.convert_to_eaddr(packet.src)
        dnsh = packet.find('dns')

        if not self.permit_ether_addr(eaddr):
            print "Dropping DNS Packet - MAC Address not allowed"
            return STOP

        if not dnsh:
            print "Invalid DNS packet:", dnsh, packet
            return CONTINUE

        print "DNS Packet:", dnsh

        for question in dnsh.questions:
            if eaddr in Homework.st['dnsList'] and question.name in Homework.st['dnsList'][eaddr]:
                print "DNS Resquest blocked for", question.name
                return STOP

        flow = util.extract_flow(packet)
        Homework.install_datapath_flow(
             dpid, flow, 3, 10,
             [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_NORMAL]]],
             buffer_id, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr
             )

        return CONTINUE
    
    def install(self):
        print "Homework Install"
        Homework.register_for_datapath_join(datapath_join)
        Homework.register_for_datapath_leave(datapath_leave)


        match_src = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                      core.NW_PROTO : ipv4.ipv4.UDP_PROTOCOL,
                      core.TP_DST : 53}
        self.register_for_packet_match(self.handle_dns, 1, match_src)

        match_src = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                      core.NW_PROTO : ipv4.ipv4.UDP_PROTOCOL,
                      core.TP_SRC : 53}
        self.register_for_packet_match(self.handle_dns_response, 1, match_src)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        self._dhcp = self.resolve(pydhcp_app)
        print self._dhcp.get_dhcp_mapping()
        self._dhcp.register_object(self)


        homeworkp = webservice.WSPathStaticString("homework")

        permit_path = (homeworkp, webservice.WSPathStaticString("permit"), WSPathEthAddress(),)
        v1.register_request(ws_permit, "POST", permit_path, """Permit an Ethernet address.""")

        permit_group_path = (homeworkp, webservice.WSPathStaticString("permit_group"))
        v1.register_request(ws_permit_group, "POST", permit_group_path, """Permit a set of  Ethernet addresses 
represented as json array in the body of the http post.""")

        dns_permit_path = (homeworkp, webservice.WSPathStaticString("dnspermit"), WSPathEthAddress(), WSPathHostName(),)
        v1.register_request(ws_dns_permit, "POST", dns_permit_path, """Permit a DNS address.""")

        dns_permit_group_path = (homeworkp, webservice.WSPathStaticString("dnspermit_group"))
        v1.register_request(ws_dns_permit_group, "POST", dns_permit_group_path, """Permit a DNS address.""")

        deny_path = (homeworkp, webservice.WSPathStaticString("deny"), WSPathEthAddress(),)
        v1.register_request(ws_deny, "POST", deny_path, """Deny an Ethernet address.""")

        deny_group_path = (homeworkp, webservice.WSPathStaticString("deny_group"))
        v1.register_request(ws_deny_group, "POST", deny_group_path, """Deny access to a set of  Ethernet addresses 
represented as json array in the body of the http post.""")

        dns_deny_path = (homeworkp, webservice.WSPathStaticString("dnsdeny"), WSPathEthAddress(), WSPathHostName(),)
        v1.register_request(ws_dns_deny, "POST", dns_deny_path, """Deny a DNS address.""")

        dns_deny_group_path = (homeworkp, webservice.WSPathStaticString("dnsdeny_group"))
        v1.register_request(ws_dns_deny_group, "POST", dns_deny_group_path, """Deny a DNS address.""")

        statusp = webservice.WSPathStaticString("status")
        status_path = (homeworkp, statusp,)
        v1.register_request(ws_status, "GET", status_path, """Status of all Ethernet addresses.""")
        status_eth_path = (homeworkp, statusp, WSPathEthAddress(),)
        v1.register_request(ws_status, "GET", status_eth_path, """Status of an Ethernet address.""")

        dhcp_status_path = (homeworkp, webservice.WSPathStaticString("dhcp_status"))
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
