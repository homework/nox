# Copyright 2011 (C) Stanford University
# 
# This file is part of NOX.
# 
# NOX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# NOX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NOX.  If not, see <http://www.gnu.org/licenses/>.
#

from nox.lib.core     import *
from nox.lib.netinet.netinet    import datapathid, ipaddr, cidr_ipaddr
import logging
import pymongo

from sets import Set
import time 

from nox.netapps.flow_fetcher.pyflow_fetcher import flow_fetcher_app

log = logging.getLogger('nox.netapps.homework_stats.homework_stats')

obj = None

def datapath_join(dpid, attrs):
    log.info(("datapath %s joined"%(dpid)))
    obj.dp.add(dpid)

def datapath_leave(dpid):
    log.info(("datapath leave"%(dpid)))
    try:
        obj.dp.remove(dpid)
    except  KeyError:
        pass

def generate_key(flow_def):
    if ("nw_src" in flow_def and  "nw_dst" in flow_def and 
            "tp_src" in flow_def and "tp_dst" in flow_def and 
            "nw_proto" in flow_def):

        if ((obj.local_netmask.matches(ipaddr(flow_def["nw_src"])) and 
            not obj.local_netmask.matches(ipaddr(flow_def["nw_dst"]))
            ) or ( obj.local_netmask.matches(ipaddr(flow_def["nw_src"]))
                and obj.local_netmask.matches(ipaddr(flow_def["nw_dst"]))
                and flow_def["nw_src"] < flow_def["nw_dst"])):
                #the src is local and the dst is remote if both are local, the lower one is the local

            return (flow_def["nw_src"], flow_def["tp_src"], flow_def["nw_dst"],
                flow_def["tp_dst"], flow_def["nw_proto"], 1)
        else:
            return (flow_def["nw_dst"], flow_def["tp_dst"], flow_def["nw_src"], 
                    flow_def["tp_src"], flow_def["nw_proto"], 0)
    else:
        return (None, None,  None,  None,  None, -1)

def update_db(loc_ip, loc_port, rem_ip, rem_port, proto, direction,
        diff_pkt, diff_byte, ts):
    recs = obj.flow_stats.find({})
    for rec in recs:
        print "%d %d:%d-%d:%d-%d-%d %d"%(rec["time"], rec["loc_ip"],
                rec["loc_port"], rec["rem_ip"], rec["rem_port"], rec["proto"],
                rec["direction"], rec["bytes"])

    rec = {
        "loc_ip" : loc_ip,
        "loc_port" : loc_port,
        "rem_ip" : rem_ip,
        "rem_port" : rem_port,
        "proto" : proto,
        "direction" : direction,
        "time" : ts,
        "bytes" : diff_byte,
        "pkt" : diff_pkt}
    obj.flow_stats.save(rec)

#    print str(rec)
#    if rec:
#        if direction == 0:
#            obj.flow_stats.update(rec, 
#                {"$push" : {"snd_pkt" : diff_pkt, "snd_ts" : ts, "rcv_byte" : diff_byte},
#              "$set": {"last_time" : ts}})
#        else:
#            obj.flow_stats.update(rec, 
#                {"$push" : {"rcv_pkt" : diff_pkt, "rcv_ts" : ts, "rcv_byte" : diff_byte},
#               "$set": {"last_time" : ts}})
#    else:
#        rec = {
#        "loc_ip" : loc_ip,
#        "loc_port" : loc_port,
#        "rem_ip" : rem_ip,
#        "rem_port" : rem_port,
#        "proto" : proto,
#        "app_name" : "",
#        "create_time" : ts,
#        "last_time" : ts,
#        "destroy_time" : 0,
#        "snd_pkt" : [],
#        "snd_ts" : [],
#        "snd_byte" : [],
#        "rcv_pkt" : [],
#        "rcv_ts": [],
#        "rcv_ts" : []}
##        print "insert rec %s"%(str(rec))
#        if direction == 0:
#            rec["snd_pkt"].append(diff_pkt)
#            rec["snd_pkt"].append(ts)
#            rec["snd_pkt"].append(diff_byte)
#        else:
#            rec["rcv_pkt"].append(diff_pkt)
#            rec["rcv_pkt"].append(ts)
#            rec["rcv_pkt"].append(diff_byte)
#        obj.flow_stats.insert(rec)


def report_results(ff):
    status = ff.get_status()
    ts = int(time.time())
    if status == 0:
        for flow in ff.get_flows():
            loc_ip, loc_port, rem_ip, rem_port, proto, direction=generate_key(flow["match"])

            if direction in (0, 1):
                key = "%d:%d-%d:%d-%d"%(loc_ip, loc_port, rem_ip, rem_port, proto)
                print "%s %d"%(key, direction)
                if(key not in obj.flow_cache):
                    obj.flow_cache[key] = {
                            "pkts" : [0,0],
                            "bytes" : [0,0]
                            }
                diff_pkt = flow["packet_count"] - obj.flow_cache[key]["pkts"][direction]
                obj.flow_cache[key]["pkts"][direction] = flow["packet_count"]
                diff_byte = flow["byte_count"] - obj.flow_cache[key]["bytes"][direction]
                obj.flow_cache[key]["bytes"][direction] = flow["byte_count"]

                update_db(loc_ip, loc_port, rem_ip, rem_port, proto, direction,
                         diff_pkt, diff_byte, ts)

def update_stats():
    log.info('one minute has passed')

    req = {"dpid" : "", "match" : {'dl_type': 0x0800,}}
    for dpid in obj.dp:
        req["dpid"] = ("\"%s\""%(str(dpid)))
        ff = obj.ffa.fetch(datapathid.from_host(dpid), req,
                lambda: report_results(ff))

        #    flow_stats.insert()
    obj.post_callback(10, update_stats)

class homework_stats(Component):
    """ \brief homework_stats
    \ingroup noxcomponents

    @author cr409
    @date 
    """
    def __init__(self, ctxt):
        """\brief Initialize
        @param ctxt context
        """
        Component.__init__(self, ctxt)
        log.debug("Initialized")
        self.dp = Set([])
        self.flow_cache = {}
        self.local_netmask = cidr_ipaddr(ipaddr("10.2.0.0"), 16)

    def install(self):
        """\brief Install
        """
        log.debug("Installed")
        global obj
        obj = self
        self.register_for_datapath_join(datapath_join)
        self.register_for_datapath_leave(datapath_leave)

        # init flow fetching application
        self.ffa = self.resolve(flow_fetcher_app)

        # register for event
        self.post_callback(10, update_stats)

        # open connection to database
        connection = pymongo.Connection()
        self.flow_stats = connection.homework_qos.test_collection
        self.flow_stats.remove({})
        log.info("Coonected to mongodb")

    def getInterface(self):
        """\brief Get interface
        """
        return str(homework_stats)

def getFactory():
    class Factory:
        def instance(self, ctxt):
            return homework_stats(ctxt)

    return Factory()
