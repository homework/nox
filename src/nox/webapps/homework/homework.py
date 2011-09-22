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

from threading import Thread

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

def deny(eaddr, ipaddr = None):
    """ Deny tx/rx to/from a specified Ethernet address. """
    print "DENY", eaddr, ipaddr
    if not (eaddr or ipaddr): return
    eaddr = util.convert_to_eaddr(eaddr)
    del Homework.st['permitted'][eaddr]
    Homework._hwdb.insert("SQL:insert into Devices values (\"%s\", \"deny\")"%(eaddr))
    #data = Homework._dhcp.revoke_mac_addr(eaddr)
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
    print Homework._hwdb.call("SQL:select * from Leases")
    return status(eaddr)


class pollThread(Thread):
    def __init__ (self):
        Thread.__init__(self)


    def run(self):
        result = Homework._hwdb.call("SQL:select * from NoxStatus")
        # Parse responses
        statuses = parseStatus(result)
        print result
        list = []
        for status in statuses:
            device = { 'mac': parseMacAddress(command.arguments), 'action': status.state }
            list.append(devce)
            
        Homework._hwdb.postEvent(list)
 
        while True:
            result = Homework._hwdb.call("SQL:select * from NoxCommand")
            print result
            # Parse responses
            commands = parseCommands(result);
            for command in commands:
                # Execute command
                list = []
                device = { 'mac': parseMacAddress(command.arguments), 'action': command.command }
                list.append(devce)
            
                Homework._hwdb.postEvent(list)
               
                # Insert result
                result = Homework._hwdb.call("SQL:insert into NoxResponse values (\"%s\", true, \"\")"%(command.command_id))
                print result
                result = Homework._hwdb.call("SQL:insert into NoxStatus values (\"%s\", \"%s\", \"%s\")"%(command.arguments, command.command, command.source))
                print result               
               
            time.sleep(1)

    def parseMacAddress(self, str):
        if str.startswith('ETH|'):
            parts = str.split('|')
            return util.convert_to_eaddr(parts[1])
        elif str.startswith('IP|'):
            parts = str.split('|')

    def parseCommands(self, str):
        result = []
        lines = str.split("\n")
        for line in lines:
            parameters = line.split("<|>")
            command = { 'time': parameters[0], 'command_id': parameters[1], 'command': parameters[2], 'arguments': parameters[3], 'source': parameters[4]}
            result.append(command);
            
        return result;

    def parseStatus(self, str):
        result = []
        lines = str.split("\n")
        for line in lines:
            parameters = line.split("<|>")
            status = { 'time': parameters[0], 'device': parameters[1], 'state': parameters[2], 'source': parameters[3]}
            result.append(status);
            
        return result;
            
    def parseResponses(self, str):
        result = []
        lines = str.split("\n")
        for line in lines:
            parameters = line.split("<|>")
            response = { 'time': parameters[0], 'command_id': parameters[1], 'success': parameters[2], 'message': parameters[3]}
            result.append(response);
            
        return result;
        
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

        self._dhcp = self.resolve(pydhcp_app)
        print self._dhcp.get_dhcp_mapping()
        self._dhcp.register_object(self)
        
        # gettting a reference for the hwdb component
        self._hwdb = self.resolve(pyhwdb)
        # print "hwdb obj " + str(self._hwdb)

        pt = pollThread()
        pt.start()
        
    def getInterface(self): return str(homework)

def getFactory():
    class Factory:
        def instance(self, ctxt): return homework(ctxt)
    return Factory()
