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

EMPTY_JSON = "{}"
TICKER = 1

class Actions:
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
    
## utility functions
    
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

## ticker
    
def ticker():
    now = time.time()
    print "TICK", now
    Homework.post_callback(TICKER, ticker)
    return True

## webservice boilerplate: URL path component types

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

## other openflow events

def datapath_join(dpid, attrs):
    ppf(("DPIDJ", dpid, attrs))
    Homework.st['ports'][dpid] = attrs['ports'][:]

    Homework.install_datapath_flow(
        dpid,
        { core.DL_TYPE: ethernet.ethernet.ARP_TYPE, },
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        Actions.flood_and_process,
        )
    Homework.install_datapath_flow(
        dpid,
        { core.DL_TYPE: ethernet.ethernet.RARP_TYPE, },
        openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
        Actions.flood_and_process,
        )

    pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE, }
    for eaddr, ipaddrs in Homework.st['permitted'].items():
        pattern[core.DL_SRC] = eaddr
        if not ipaddrs: 
            Homework.install_datapath_flow(
                dpid, pattern,
                openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
                Actions.really_flood
                )
##         else:
##             for ipaddr in ipaddrs:
##                 pattern[core.NW_SRC] = ipaddr
##                 Homework.install_datapath_flow(
##                     dpid, pattern,
##                     openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
##                     Actions.really_flood
##                     )
##             del pattern[core.NW_SRC]                

    print "DONE"
    
def datapath_leave(dpid):
    ppf(("DPIDL", dpid, Homework.st['ports'][dpid]))
    del Homework.st['ports'][dpid]
    ppf(("\t", Homework.st['ports']))

def table_stats_in(dpid, tables):
    ppf(("TSI", dpid, tables))
    ppf(("\t", Homework.st['ports']))
    ppf(("\t", Homework.st['permitted']))

## webservice entry points
        
def permit(eaddr, ipaddr=None):

    ## NB. note that traffic will not necessarily start flowing
    ## immediately in the case that the router needs to ARP for it.
    ## not sure why - possibly some negative result caching going on?
    
    print "PERMIT", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    eaddr = util.convert_to_eaddr(eaddr)
    pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.DL_SRC: eaddr,
                }
##     old_ipaddrs = None
    if not ipaddr:
        old_ipaddrs = Homework.st['permitted'].get(eaddr)
        Homework.st['permitted'][eaddr] = None

##     else:
##         ipaddr = util.convert_to_ipaddr(ipaddr)
        
##         try: Homework.st['permitted'][eaddr].append(ipaddr)
##         except: Homework.st['permitted'][eaddr] = [ipaddr]

##         pattern[core.NW_SRC] = ipaddr

    for dpid in Homework.st['ports']:
        ## permit the forward path to this eaddr, and ipaddr if specified
        Homework.install_datapath_flow(
            dpid, pattern,
            openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
            Actions.really_flood,
            )

        ## ...and the reverse path similarly
        del pattern[core.DL_SRC]
        pattern[core.DL_DST] = eaddr
        if ipaddr:
            del pattern[core.NW_SRC]
            pattern[core.NW_DST] = ipaddr
        
        Homework.install_datapath_flow(
            dpid, pattern,
            openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
            Actions.really_flood,
            )

##         if old_ipaddrs:
##             for ipaddr in old_ipaddrs:
##                 pattern[core.NW_SRC] = ipaddr
##                 Homework.delete_strict_datapath_flow(dpid, pattern)

    ## permit IP from MAC, specifying IP addr if available
##     prio = openflow.OFP_DEFAULT_PRIORITY
##     rules = { core.DL_TYPE: ethernet.ethernet.IP_TYPE, }
##     rules[core.DL_SRC] = eaddr
##     if ipaddr:
##         rules[core.NW_SRC] = ipaddr
##     Homework.register_for_packet_match(match_mac_src, prio, rules)

##     del rules[core.DL_SRC]
##     rules[core.DL_DST] = eaddr
##     if ipaddr:
##          del rules[core.NW_SRC]
##          rules[core.NW_DST] = ipaddr
##     Homework.register_for_packet_match(match_mac_dst, prio, rules)

    return EMPTY_JSON

def ws_permit(request, args):
    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")

    ipaddr = args.get('ipaddr')
    return permit(eaddr, ipaddr)

def deny(eaddr, ipaddr):
    print "DENY", eaddr, ipaddr
    if not (eaddr or ipaddr): return 
    
    eaddr = util.convert_to_eaddr(eaddr)
    pattern = { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
                core.DL_SRC: eaddr,
                }
##     if ipaddr: ipaddrs = [ util.convert_to_ipaddr(ipaddr) ]
##     else:
##         ipaddrs = Homework.st['permitted'][eaddr]
        
    for dpid in Homework.st['ports']:
        Homework.delete_strict_datapath_flow(dpid, pattern)
        ## ...and the reverse path similarly
        del pattern[core.DL_SRC]
        pattern[core.DL_DST] = eaddr
        Homework.delete_strict_datapath_flow(dpid, pattern)

##         if ipaddr:
##             del pattern[core.NW_SRC]
##             pattern[core.NW_DST] = ipaddr


##         if not ipaddrs: continue
##         for ipaddr in ipaddrs:
##             pattern[core.NW_SRC] = ipaddr
##             Homework.delete_strict_datapath_flow(dpid, pattern)

    return EMPTY_JSON

def ws_deny(request, args):
    ppf(("REQUEST", request))
    ppf(("ARGS", args))
    ppf(("ST", Homework.st))

    eaddr = args.get('eaddr')
    if not eaddr: return webservice.badRequest(request, "missing eaddr")
    ipaddr = args.get('ipaddr')

    return deny(eaddr, ipaddr)

## main

class homework(core.Component):

    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)

        global Homework
        Homework = self
        Homework.st = { 'permitted': {}, ## eaddr -> None ## [ipaddr, ...]
                        'ports': {},     ## dpid -> attrs
                        }
        
    def install(self):
##         Homework.post_callback(TICKER, ticker)

        Homework.register_for_datapath_join(datapath_join)
        Homework.register_for_datapath_leave(datapath_leave)
        Homework.register_for_table_stats_in(table_stats_in)

##         prio = openflow.OFP_DEFAULT_PRIORITY
##         rules = { core.DL_TYPE: ethernet.ethernet.ARP_TYPE,
##                   }
##         Homework.register_for_packet_match(match_arp, prio, rules)

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


########################################################################

## actual state manipulation

## packet match events

## def match_arp(dpid, inport, reason, flen, bufid, packet):
##     print "*", inport, dpid, packet
    
##     Homework.install_datapath_flow(
##         dpid,
##         { core.DL_TYPE: ethernet.ethernet.ARP_TYPE, },
##         openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
##         Actions.flood_and_process,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)
##     Homework.install_datapath_flow(
##         dpid,
##         { core.DL_TYPE: ethernet.ethernet.RARP_TYPE, },
##         openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
##         Actions.flood_and_process,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)

##     return core.CONTINUE

## def match_self(dpid, inport, reason, flen, bufid, packet):
##     print "=", inport, dpid, packet
##     return core.CONTINUE
    
## def match_mac_src(dpid, inport, reason, flen, bufid, packet):
##     print "<", packet

##     flow = core.extract_flow(packet)
##     Homework.install_datapath_flow(
##         dpid,
##         { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
##           core.DL_SRC: flow['dl_src'],
##           },
##         openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
##         Actions.really_flood,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)

##     return core.CONTINUE

## def match_mac_dst(dpid, inport, reason, flen, bufid, packet):
##     print ">", packet

##     flow = core.extract_flow(packet)
##     Homework.install_datapath_flow(
##         dpid,
##         { core.DL_TYPE: ethernet.ethernet.IP_TYPE,
##           core.DL_DST: flow['dl_dst'],
##           },
##         openflow.OFP_FLOW_PERMANENT, openflow.OFP_FLOW_PERMANENT,
##         Actions.really_flood,
##         bufid, openflow.OFP_DEFAULT_PRIORITY, inport, packet.arr)

##     return core.CONTINUE

########################################################################

## IDLE_TIMEOUT = 10
## CONTROLLER_MAC_ADDR = util.convert_to_eaddr("d4:9a:20:d2:52:8e") ## greyjay
## CONTROLLER_IP_ADDR = util.convert_to_ipaddr("128.243.35.223")    ## greyjay
## NOX_MAC_ADDRS = ( util.convert_to_eaddr(e) for e in
##                   ("00:23:20:85:69:d0", ## dp0
##                    "00:0c:f1:e2:e3:20", ## eth0
##                    ))
