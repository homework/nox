# Copyright (C) 2010 Richard Mortier <mort@cantab.net>.  All Rights
# Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
# USA.

import pprint, time, re
ppf = pprint.pprint

from nox.webapps.webservice import webservice

from nox.lib import core, openflow, packet, util
from nox.lib.packet import ethernet, ipv4

Homework = None

TICKER = 1
IDLE_TIMEOUT = 10
CONTROLLER_MAC_ADDR = util.convert_to_eaddr("d4:9a:20:d2:52:8e")
CONTROLLER_IP_ADDR = util.convert_to_ipaddr("128.243.35.223")
NOX_MAC_ADDRS = ( util.convert_to_eaddr(e) for e in
                  ("00:23:20:85:69:d0", ## dp0
                   "00:0c:f1:e2:e3:20", ## eth0
                   ))

def invert_flow(flow):
    s, d = flow['dl_src'], flow['dl_dst']
    flow['dl_src'], flow['dl_dst'] = d, s

    s, d = flow['nw_src'], flow['nw_dst']
    flow['nw_src'], flow['nw_dst'] = d, s
    
    return flow

def is_valid_ip(ip):
    quads = ip.split(".")
    if len(quads) != 4: return False

    try: return reduce(lambda acc,quad: (0 <= quad <= 255) and acc, map(int, quads), True)
    except ValueError: return False

def is_valid_eth(eth):
    if ":" in eth: bytes = eth.split(":")
    elif "-" in eth: bytes = eth.split("-")
    else: return False ## else: bytes = [ eth[i:i+2] for i in range(0,len(eth),2) ]

    if len(bytes) != 6: return False    

    try: return reduce(lambda acc,byte: (0 <= byte <= 256) and acc,
                       map(lambda b: int(b,16), bytes), True)
    except ValueError: return False
               
def ticker():
    now = time.time()
    print "TICK", now
    Homework.post_callback(TICKER, ticker)
    return True

def match_self(dpid, inport, reason, flen, bufid, packet):
    print "=", inport, dpid, packet

    return core.CONTINUE
    
def match_arp(dpid, inport, reason, flen, bufid, packet):
    print "+", inport, dpid, packet
    flow = core.extract_flow(packet)
    
    if flow['dl_type'] in (0x8100,): ## XXX why?!  this should only match on ARPs
        return core.CONTINUE
    
    actions = [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]],
               [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_IN_PORT]],
               ]
    Homework.install_datapath_flow(
        dpid, flow, 0,0, actions,
        bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)    
    return core.CONTINUE

def match_mac(dpid, inport, reason, flen, bufid, packet):
    print "*", packet
    flow = core.extract_flow(packet)
    actions = [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_FLOOD]],
               [openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_IN_PORT]],
               ]
    Homework.install_datapath_flow(
        dpid, flow, 0,0, actions,
        bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)

    return core.CONTINUE

def permit(eaddr, ipaddr=None):
    print "PERMIT", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    global Homework

    eaddr = util.convert_to_eaddr(eaddr)
    if ipaddr: ipaddr = util.convert_to_ipaddr(ipaddr)

    print "\t", eaddr, ipaddr
                                        
    ## permit ARP
    prio = openflow.OFP_DEFAULT_PRIORITY
    rules = { core.DL_TYPE: ethernet.ethernet.ARP_TYPE, }
    rules[core.DL_SRC] = eaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    del rules[core.DL_SRC]
    rules[core.DL_DST] = eaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    ## permit RARP
    rules = { core.DL_TYPE: ethernet.ethernet.RARP_TYPE, }
    rules[core.DL_SRC] = eaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    del rules[core.DL_SRC]
    rules[core.DL_DST] = eaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    ## permit IP, also specifying IP addr if given
    rules = { core.DL_TYPE: ethernet.ethernet.IP_TYPE, }
    rules[core.DL_SRC] = eaddr
    if ipaddr:
        rules[core.NW_SRC] = ipaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    del rules[core.DL_SRC]
    rules[core.DL_DST] = eaddr
    if ipaddr:
         del rules[core.NW_SRC]
         rules[core.NW_DST] = ipaddr
    Homework.register_for_packet_match(match_mac, prio, rules)

    return ""

def ws_permit(request, args):
    eaddr = args.get('eaddr')
    if not eaddr:  return webservice.badRequest(request, "missing eaddr")
    ipaddr = args.get('ipaddr')

    return permit(eaddr, ipaddr)

def ws_deny(request, args):
    print request
    print args

class WSPathIPAddress(webservice.WSPathComponent):
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
    def __init__(self):
        webservice.WSPathComponent.__init__(self)

    def __str__(self): return "eaddr"

    def extract(self, pc, data):
        if not pc:
            return webservice.WSPathExtractResult(error="End of requested URI")

        if not is_valid_eth(pc):
            return webservice.WSPathExtractResult(error="invalid Ethernet address '%s'" % (pc,))

        return webservice.WSPathExtractResult(pc)

class homework(core.Component):

    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global Homework
        Homework = self
        Homework.st = {}        
        
    def install(self):
        Homework.post_callback(TICKER, ticker)

        prio = openflow.OFP_DEFAULT_PRIORITY
        rules = { core.DL_TYPE: ethernet.ethernet.ARP_TYPE,
##                   core.DL_DST: ethernet.ETHER_BROADCAST,
                  }
        Homework.register_for_packet_match(match_arp, prio, rules)

##         for eaddr in NOX_MAC_ADDRS:
##             print str(eaddr)
##             rules = { core.DL_SRC: eaddr, }
##             Homework.register_for_packet_match(match_self, prio, rules)
##             rules = { core.DL_DST: eaddr, }
##             Homework.register_for_packet_match(match_self, prio, rules)

        ws = self.resolve(str(webservice.webservice))
        v1 = ws.get_version("1")

        homeworkp = webservice.WSPathStaticString("homework")

        permitp = webservice.WSPathStaticString("permit")
        permit_eth_path = (homeworkp, permitp, WSPathEthAddress(),)
        permit_ip_path = (homeworkp, permitp, WSPathEthAddress(), WSPathIPAddress(),)
        v1.register_request(ws_permit, "PUT", permit_eth_path, """Permit an Ethernet address.""")
        v1.register_request(ws_permit, "PUT", permit_ip_path, """Permit an IP address.""")

        denyp = webservice.WSPathStaticString("deny")
        deny_eth_path = (homeworkp, denyp, WSPathEthAddress(),)
        deny_ip_path = (homeworkp, denyp, WSPathEthAddress(), WSPathIPAddress(),)
        v1.register_request(ws_deny, "PUT", deny_eth_path, """Deny an Ethernet address.""")
        v1.register_request(ws_deny, "PUT", deny_ip_path, """Deny an IP address.""")
    
    def getInterface(self): return str(homework)

def getFactory():
    class Factory:
        def instance(self, ctxt): return homework(ctxt)

    return Factory()

########################################################################


## from wsgiref.simple_server import make_server

##
    
## def is_post_request(environ):
##     if environ['REQUEST_METHOD'].upper() != 'POST':
##         return False
##     content_type = environ.get('CONTENT_TYPE', 'application/x-www-form-urlencoded')
##     return (content_type.startswith('application/x-www-form-urlencoded'
##                                     or content_type.startswith('multipart/form-data')))

## def app(environ, start_response):
##     print "ENV\n", environ
##     if is_post_request(environ): 
##         postdata = environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))
##         print(postdata)
    
##     status, headers = '200 OK', []
##     start_response(status, headers)
##     return [""]

## def httpd_worker():
##     global Homework
##     Homework.st['httpd'] = make_server('', HW_CONTROLLER_PORT, app)
##     Homework.st['httpd'].serve_forever()

##

## def port_status(dpid, reason, attrs):
##     ppf(("PS", dpid, reason, attrs))
##     return core.CONTINUE

## def flow_removed(arg):
##     ppf(("FR", arg.__dict__))
##     return core.CONTINUE

## def flow_mod(arg):
##     ppf(("FM", arg.__dict__))
##     return core.CONTINUE

## def match_icmp(dpid, inport, reason, flen, bufid, packet):
##     print "ICMP\n\t", "%x" % (dpid,), inport, reason, flen, bufid
##     flow = core.extract_flow(packet)
##     print "\t\t", flow                                    
##     actions = [[openflow.OFPAT_OUTPUT, [0, openflow.OFPP_FLOOD]],
##                ]
##     Homework.install_datapath_flow(
##         dpid, flow, 0, 0, actions,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)
    
##     return core.STOP


## def match_tcp(dpid, inport, reason, flen, bufid, packet):
##     print "TCP\n\t", "%x" % (dpid,), inport, reason, flen, bufid, packet
##     flow = core.extract_flow(packet)
##     print "\t\t", flow

##     if 9999 == flow[core.TP_SRC]:
##         actions = [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_CONTROLLER]]]
##     else:
##         actions = [[openflow.OFPAT_OUTPUT, [0, openflow.OFPP_FLOOD]]]
    
##     Homework.install_datapath_flow(
##         dpid, flow, 0, 0, actions,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)
    
##     return core.CONTINUE

## def packet_in(dpid, inport, reason, flen, bufid, packet):
##     flow = core.extract_flow(packet)
## ##     print "PI\t", flow, flen
## ##     actions = [[openflow.OFPAT_OUTPUT, [0, openflow.OFPP_FLOOD]], #ALL]],
## ##                ]
## ##     Homework.install_datapath_flow(
## ##         dpid, flow, 0, 0, actions,
## ##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)
    
##     return core.CONTINUE

## def datapath_join(dpid, attrs):
##     ppf(("DPIDJ", dpid, attrs))
##     Homework.st['ports'] = attrs['ports'][:]

##     actions = [[openflow.OFPAT_OUTPUT, [-1, openflow.OFPP_CONTROLLER]],
##                ]
## ##     Homework.install_datapath_flow(
## ##         dpid, { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
## ##                 core.NW_PROTO: ipv4.ipv4.ICMP_PROTOCOL,
## ##                 },
## ##         0, 0, actions)

##     attrs = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
##               core.NW_PROTO: ipv4.ipv4.TCP_PROTOCOL,
##               core.TP_SRC: HW_CONTROLLER_PORT,
##               }
##     Homework.install_datapath_flow(dpid, attrs, 0, 0, actions)
    
##     actions.append([openflow.OFPAT_OUTPUT, [0, openflow.OFPP_ALL]])
##     del attrs[core.TP_SRC]
##     attrs[core.TP_DST] = HW_CONTROLLER_PORT
##     Homework.install_datapath_flow(dpid, attrs, 0, 0, actions)
    
##     return core.CONTINUE

## def datapath_leave(dpid):
##     ppf(("DPIDL", dpid))

##


##         self.register_for_datapath_join(datapath_join)
##         self.register_for_datapath_leave(datapath_leave)
##         self.register_for_flow_removed(flow_removed)
##         self.register_for_flow_mod(flow_mod)

##         Homework.register_for_packet_match(
##             match_icmp, openflow.OFP_DEFAULT_PRIORITY,
##             { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
##               core.NW_PROTO: ipv4.ipv4.ICMP_PROTOCOL,
##               })

##         Homework.register_for_packet_match(
##             match_tcp, openflow.OFP_DEFAULT_PRIORITY,
##             { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
##               core.NW_PROTO: ipv4.ipv4.TCP_PROTOCOL,
##               })        

##         Homework.st['httpd_thread'] = threading.Thread(target=httpd_worker)
##         Homework.st['httpd_thread'].setDaemon(True)
##         Homework.st['httpd_thread'].start()
