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

import sys, traceback
import time, re

from nox.netapps.hwdb.pyhwdb import pyhwdb

from nox.lib import core, util

Homework = None


##
## utility functions
##

def is_valid_ip(ip):
    """ Test if string is valid representation of IP address. """
    quads = ip.split(".")
    if len(quads) != 4: return False

    try: return reduce(lambda acc, quad: (0 <= quad <= 255) and acc, map(int, quads), True)
    except ValueError: return False

def is_valid_eth(eth):
    """ Test if string is valid representation of Ethernet address. """
    if not eth: return False
    bytes = eth.split(":")

    if len(bytes) != 6: return False

    try: return reduce(lambda acc, byte: (0 <= byte <= 256) and acc,
                       map(lambda b: int(b, 16), bytes), True)
    except ValueError: return False

def formatMacAddress(mac):
    if "-" in mac:
        return mac.replace("-", ":")
    if ":" in mac:
        return mac

    return mac[0:2] + ":" + mac[2:4] + ":" + mac[4:6] + ":" + mac[6:8] + ":" + mac[8:10] + ":" + mac[10:12]

def getMacAddress(str):
    if str.startswith('ETH|'):
        parts = str.split('|')
        return formatMacAddress(parts[1])

    elif str.startswith('IP|'):
        parts = str.split('|')
        ip = parts[1]
        if not is_valid_ip(ip):
            return None
        result = Homework._hwdb.call("SQL:SELECT * from Leases WHERE ipaddr = \"{}\"".format(ip))
        leases = parseResult(result)
        if len(leases) == 0:
            return None
        return leases[len(leases) - 1]['macaddr']
    else:
        return str

def parseResult(str):
    result = []
    lines = str.split("\n")
    del lines[0]
    if len(lines) == 0:
        return result
    if len(lines[0]) == 0:
        return result

    headLine = lines[0].split("<|>")
    del lines[0]
    headers = []
    for header in headLine:
        if len(header) == 0:
            continue
        columnInfo = header.split(":")
        headers.append(columnInfo[1])

    for line in lines:
        if len(line) == 0:
            continue
        parameters = line.split("<|>")
        resultItem = dict()
        for i in range(len(headers)):
            resultItem[headers[i]] = parameters[i]

        result.append(resultItem)

    return result

def timer():
    try:
        query = "SQL:SELECT * from NoxCommand"
        if Homework.last:
            query = "SQL:SELECT * from NoxCommand [ since {} ]".format(Homework.last)
        result = Homework._hwdb.call(query)
        # Parse responses
        commands = parseResult(result);
        for command in commands:
            # Execute command

            mac = getMacAddress(command['arguments'])
            Homework.last = command['timestamp']
            if is_valid_eth(mac):
                device = { 'mac': mac, 'action': command['command'] }
                devices = [ device ]

                Homework._hwdb.postEvent(devices)

                # Insert result
                Homework._hwdb.call("SQL:INSERT into NoxResponse values (\"{}\", '1', \"Success\")".format(command['commandid']))
                Homework._hwdb.call("SQL:INSERT into NoxStatus values (\"{}\", \"{}\", \"{}\") on duplicate key update".format(mac, command['command'], command['source']))
            elif not mac:
                Homework._hwdb.call("SQL:INSERT into NoxResponse values (\"{}\", '0', \"Could not find MAC Address for {}\")".format(command['commandid'], command['arguments']))
            else:
                Homework._hwdb.call("SQL:INSERT into NoxResponse values (\"{}\", '0', \"{} not recognized as a MAC Address\")".format(command['commandid'], mac))

    except:
        traceback.print_exc(file = sys.stdout)

    Homework.post_callback(1, timer)


def setup():
    try:
        result = Homework._hwdb.call("SQL:select * from NoxStatus")
        # Parse responses
        statuses = parseResult(result)
        devices = []
        for status in statuses:
            device = { 'mac': getMacAddress(status['device']), 'action': status['state'] }
            devices.append(device)
            Homework.last = status['timestamp']

        if len(devices) > 0:
            print "Posting changes:", devices
            Homework._hwdb.postEvent(devices)
    except:
        traceback.print_exc(file = sys.stdout)

##
## main
##

class homework(core.Component):
    """ Main application. """

    def __init__(self, ctxt):
        core.Component.__init__(self, ctxt)
        global Homework
        Homework = self
        Homework.last = None

    def install(self):
        # gettting a reference for the hwdb component
        self._hwdb = self.resolve(pyhwdb)
        # print "hwdb obj " + str(self._hwdb)

        setup()

        self.post_callback(1, timer)

    def getInterface(self): return str(homework)

def getFactory():
    class Factory:
        def instance(self, ctxt): return homework(ctxt)
    return Factory()
