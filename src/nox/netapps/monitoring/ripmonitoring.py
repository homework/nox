'''Ripcord monitoring core'''

# Author: Rean Griffith (rean@eecs.berkeley.edu)

import time
import logging
from collections import defaultdict
from collections import deque
from twisted.python import log

from nox.coreapps.pyrt.pycomponent import Table_stats_in_event, \
Aggregate_stats_in_event
from nox.lib.core import Component, Flow_mod_event, Datapath_join_event, \
Datapath_leave_event, Port_stats_in_event, Table_stats_in_event, \
Aggregate_stats_in_event, Flow_stats_in_event, Queue_stats_in_event, \
CONTINUE, STOP, pyevent
import nox.lib.openflow as openflow
from nox.lib.packet.packet_utils  import mac_to_str
from nox.lib.netinet.netinet import datapathid, create_ipaddr, c_htonl, \
c_ntohl
from nox.lib.directory import Directory
from nox.lib.directory import LocationInfo
from nox.lib.openflow import OFPST_TABLE, OFPST_PORT, OFPST_AGGREGATE, \
OFPST_FLOW, OFPST_QUEUE, OFPP_NONE, OFPT_STATS_REQUEST, ofp_match, \
OFPP_ALL, OFPQ_ALL, ofp_stats_request, ofp_aggregate_stats_request, \
ofp_port_stats_request 
from nox.lib.packet.packet_utils import longlong_to_octstr
from nox.ripcordapps.configuration.configuration import configuration
from nox.ripcordapps.topodb.topodb import topodb
from nox.ripcordapps.topodb.topodb import Subset
from nox.ripcordapps.dispatch_server.dispatch_server import DispatchServer
# Import custom events for communicating with the DispatchServer
from nox.ripcordapps.dispatch_server.toporeplyevent import \
TopologyReplyEvent
from nox.ripcordapps.monitoring.linkutilreplyevent import \
LinkUtilizationReplyEvent
from nox.ripcordapps.monitoring.switchqueryreplyevent import \
SwitchQueryReplyEvent

from nox.ripcordapps.monitoring.linkadmindownevent import LinkAdminDownEvent
from nox.ripcordapps.monitoring.linkadminupevent import LinkAdminUpEvent
from nox.ripcordapps.monitoring.nodeenterevent import NodeEnterEvent
from nox.ripcordapps.monitoring.nodeexitevent import NodeExitEvent

from nox.ripcordapps.monitoring.porterrorevent import PortErrorEvent
from nox.ripcordapps.monitoring.silentswitchevent import SilentSwitchEvent
from nox.ripcordapps.monitoring.switchadmindownevent import \
SwitchAdminDownEvent
from nox.ripcordapps.monitoring.switchadminupevent import SwitchAdminUpEvent

from ripcord import openflow as of
from ripcord.config import RipcordConfiguration

# Default values for the periodicity of polling for each class of
# statistic

# Use a poll frequency of 20ms per switch (this frequency works)
#DEFAULT_POLL_TABLE_STATS_PERIOD     = 0.02
#DEFAULT_POLL_PORT_STATS_PERIOD      = 0.03
#DEFAULT_POLL_AGGREGATE_STATS_PERIOD = 0.04

# For testing, poll less aggressively
DEFAULT_POLL_TABLE_STATS_PERIOD     = 1 # seconds
DEFAULT_POLL_PORT_STATS_PERIOD      = 1 # seconds
DEFAULT_POLL_AGGREGATE_STATS_PERIOD = 1 # seconds

# Arbitrary limits on how much stats history we keep per switch
DEFAULT_COLLECTION_EPOCH_DURATION = 10 # seconds
DEFAULT_MAX_STATS_SNAPSHOTS_PER_SWITCH = 10

# Get around temporary LB4 stats limitation by estimating bytes from pkts
FAKE_BPS_FROM_PKTS = False
AVG_PKT_SIZE = 1000 * 8 # bits

# Static log handle
lg = logging.getLogger('monitoring')

## \ingroup noxcomponents
# Collects and maintains switch and port stats for the network.  
#
# Monitors switch and port stats by sending out port_stats requests
# periodically to all connected switches.  
#
# The primary method of accessing the ports stats is through the
# webserver (see switchstatsws.py)  however, components can also
# register port listeners which are called each time stats are
# received for a particular port.
#
SUB_POD = 2
SUBSET = 1
ALL = 0

nodesAllowedPod = [0x201, 0x301, 0x1, 0x101]
nodesAllowedSub = [0x40101, 0x40102, 0x201, 0x10201, 0x1, 0x10001, 0x2, 0x10002]
nodesAllowedAll = None

service_A_Nodes = [0x40101, 0x40102, 0x201, 0x301, 0x10201, 0x1, 0x101, \
0x10001]
service_A_Hosts = [0x2, 0x3, 0x102, 0x103, 0x10002]
#service_A_Links = []
service_B_Nodes = [0x40102, 0x40201, 0x10201, 0x10301, 0x20201, 0x10001, \
0x10101, 0x20001]
service_B_Hosts = [0x10003, 0x10102, 0x10103, 0x20002, 0x20003]
#service_B_Links = []

class PortCapability: 
    """Class keeps track of port capabilities/capcity"""
    def __init__(self):
        self.port_name = ""
        self.port_number = -1                                                  
        self.port_enabled = False                                              
        self.link_enabled = False                                              
        self.supports_10Mb_hd = False                                          
        self.supports_10Mb_fd = False                                          
        self.supports_100Mb_hd = False                                         
        self.supports_100Mb_fd = False                                         
        self.supports_1Gb_hd = False                                           
        self.supports_1Gb_fd = False                                           
        self.supports_10Gb_fd = False                                          
        self.max_speed = 0                                                     
        self.full_duplex = False   
    
    def compute_max_port_speed_bps(self):
        """Compute the max port speed in bps"""
        if self.supports_10Gb_fd == True:
            #print "supports 10gb"
            self.max_speed = 10000 * 1e6
        elif self.supports_1Gb_hd == True or self.supports_1Gb_fd == True:
            #print "supports 1gb"
            self.max_speed = 1000 * 1e6
        elif self.supports_100Mb_hd == True or self.supports_100Mb_fd == True:
            #print "supports 100mb"
            self.max_speed = 100 * 1e6
        elif self.supports_10Mb_hd == True or self.supports_10Mb_fd == True:
            #print "supports 10mb"
            self.max_speed = 10 * 1e6
        else:
            self.max_speed = 0
        return self.max_speed
    
    def to_dict(self):
        dict = {}
        dict['port_name'] = self.port_name
        dict['port_number'] = self.port_number
        dict['port_enabled'] = self.port_enabled
        dict['max_speed'] = self.compute_max_port_speed_bps()
        dict['full_duplex'] = self.supports_10Gb_fd or self.supports_1Gb_fd\
            or self.supports_100Mb_fd or self.supports_10Mb_fd
        return dict

class PortUtilization:
    """Class stores port tx/rx utilization"""
    def __init__(self):
        self.dpid = -1
        self.port = -1
        self.gbps_transmitted = 0.0
        self.gbps_received = 0.0

class PortInfo:
    """Class keeps track of port capabilities and recent usage"""
    def __init__(self, port_capabilities, monitoring_module):
        """Init 
        @param port_capabilities - port capacity data
        """
        self.owner_snapshot = None # Snapshot we belong to
        self.port_cap = port_capabilities
        self.port_number = -1
        self.monitoring = monitoring_module
        # Per-port counters
        self.total_rx_bytes = -1
        self.total_tx_bytes = -1
        self.total_rx_packets = -1
        self.total_tx_packets = -1
        self.total_rx_packets_dropped = -1
        self.total_tx_packets_dropped = -1
        self.total_rx_errors = -1
        self.total_tx_errors = -1
        # changes in port stats data since the last collection epoch
        self.delta_rx_bytes = -1
        self.delta_tx_bytes = -1
        self.delta_rx_packets = -1
        self.delta_tx_packets = -1
        self.delta_rx_packets_dropped = -1
        self.delta_tx_packets_dropped = -1
        self.delta_rx_errors = -1
        self.delta_tx_errors = -1

    def to_dict(self):
        dict = {}
        dict['port_number'] = self.port_number
        # Save the nested capabilities structure
        dict['port_cap'] = self.port_cap.to_dict()
        # Counters
        dict['total_rx_bytes'] = self.total_rx_bytes
        dict['total_tx_bytes'] = self.total_tx_bytes
        dict['total_rx_packets'] = self.total_rx_packets
        dict['total_tx_packets'] = self.total_tx_packets
        dict['total_rx_packets_dropped'] = self.total_rx_packets_dropped
        dict['total_tx_packets_dropped'] = self.total_tx_packets_dropped
        dict['total_rx_errors'] = self.total_rx_errors
        dict['total_tx_errors'] = self.total_tx_errors
        # Deltas
        dict['delta_rx_bytes'] = self.delta_rx_bytes
        dict['delta_tx_bytes'] = self.delta_tx_bytes
        dict['delta_rx_packets'] = self.delta_rx_packets
        dict['delta_tx_packets'] = self.delta_tx_packets
        dict['delta_rx_packets_dropped'] = self.delta_rx_packets_dropped
        dict['delta_tx_packets_dropped'] = self.delta_tx_packets_dropped
        dict['delta_rx_errors'] = self.delta_rx_errors
        dict['delta_tx_errors'] = self.delta_tx_errors
        return dict

    def print_stats(self):
        """Print per-port stats to stdout"""
        print "port number             : %d" % (self.port_number)
        #print "port speed (bps)        : %f" % \
        #       (self.port_cap[self.port_number].compute_max_port_speed_bps())
        print "port speed (bps)        : %f" % \
            (self.port_cap.compute_max_port_speed_bps())
        print "ttl rx bytes            : %d" % (self.total_rx_bytes)
        print "ttl tx bytes            : %d" % (self.total_tx_bytes)
        print "ttl rx packets          : %d" % (self.total_rx_packets)
        print "ttl tx packets          : %d" % (self.total_tx_packets)
        print "ttl rx packets dropped  : %d" % (self.total_rx_packets_dropped)
        print "ttl tx packets dropped  : %d" % (self.total_tx_packets_dropped)
        print "ttl rx errors           : %d" % (self.total_rx_errors)
        print "ttl tx errors           : %d" % (self.total_tx_errors)
        print "delta rx bytes          : %d" % (self.delta_rx_bytes)
        print "delta tx bytes          : %d" % (self.delta_tx_bytes)
        print "delta rx packets        : %d" % (self.delta_rx_packets)
        print "delta tx packets        : %d" % (self.delta_tx_packets)
        print "delta rx packets dropped: %d" % (self.delta_rx_packets_dropped)
        print "delta tx packets dropped: %d" % (self.delta_tx_packets_dropped)
        print "delta rx errors         : %d" % (self.delta_rx_errors)
        print "delta tx errors         : %d" % (self.delta_tx_errors)
        print "bits rx/sec             : %f" % \
                           (self.estimate_bits_received_per_sec())
        print "bits tx/sec             : %f" % \
                           (self.estimate_bits_sent_per_sec())
        print "packets rx/sec          : %f" % \
                             (self.estimate_packets_received_per_sec())
        print "packets tx/sec          : %f" % \
                                 (self.estimate_packets_sent_per_sec())
        print "rx utilization          : %f" % \
                                 (self.estimate_port_rx_utilization())
        print "tx utilization          : %f" % \
                                 (self.estimate_port_tx_utilization())
        
    def compute_delta_from(self, rhs, send_alarm = True):
        """Compute the counter and epoch deltas between this snapshot 
        and another (rhs)
        @param rhs - port info object to compute delta from
        """
        self.delta_rx_bytes = max(0, self.total_rx_bytes - rhs.total_rx_bytes)
        self.delta_tx_bytes = max(0, self.total_tx_bytes - rhs.total_tx_bytes)
        self.delta_rx_packets = max(0, \
                                self.total_rx_packets - rhs.total_rx_packets)
        self.delta_tx_packets = max(0,\
                                 self.total_tx_packets - rhs.total_tx_packets)
        self.delta_rx_packets_dropped = max(0, \
                                      self.total_rx_packets_dropped - \
                                        rhs.total_rx_packets_dropped)
        self.delta_tx_packets_dropped = max(0,\
                                        self.total_tx_packets_dropped - \
                                        rhs.total_tx_packets_dropped)
        self.delta_rx_errors = max(0,\
                                 self.total_rx_errors - rhs.total_rx_errors)
        self.delta_tx_errors = max(0,\
                                 self.total_tx_errors - rhs.total_tx_errors)
        
        port_has_problems = False
        if self.delta_rx_packets_dropped > 0 or \
                self.delta_tx_packets_dropped > 0:
            port_has_problems = True
        elif self.delta_rx_errors > 0 or self.delta_tx_errors > 0:
            port_has_problems = True
        
        if port_has_problems and send_alarm:
            # Post a custom port error event
             portError = PortErrorEvent( -1, self.owner_snapshot.dpid, \
                                              self.port_number )
             portError.rx_dropped = self.delta_rx_packets_dropped
             portError.tx_dropped = self.delta_tx_packets_dropped
             portError.rx_errors = self.delta_rx_errors
             portError.tx_errors = self.delta_tx_errors
             self.post( pyevent( PortErrorEvent.NAME, portError ) )

        '''
        lg.debug( "port number      : %d" % (self.port_number) )
        lg.debug( "delta bytes rx   : %d" % (self.delta_rx_bytes) )
        lg.debug( "delta bytes tx   : %d" % (self.delta_tx_bytes) )
        lg.debug( "rx bps           : %d" % \
                      (self.estimate_bits_received_per_sec()) )
        lg.debug( "tx bps           : %d" % \
                      (self.estimate_bits_sent_per_sec()) )
        '''
        #lg.debug( "delta pkts rx    : %d" % (self.delta_rx_packets) )
        #lg.debug( "delta pkts tx    : %d" % (self.delta_tx_packets) )
        #lg.debug( "delta rx pkts drp: %d" % (self.delta_rx_packets_dropped) )
        #lg.debug( "delta tx pkts drp: %d" % (self.delta_tx_packets_dropped) )
        #lg.debug( "delta rx errors  : %d" % (self.delta_rx_errors) )
        #lg.debug( "delta tx errors  : %d" % (self.delta_tx_errors) )
        
    def compute_max_port_speed_bps(self):
        """Compute the max port speed in bps"""
        if self.port_cap.supports_10Gb_fd:
            self.port_cap.max_speed = 10000 * 1e6
        elif self.port_cap.supports_1Gb_hd or self.port_cap.supports_1Gb_fd:
            self.port_cap.max_speed = 1000 * 1e6
        elif self.port_cap.supports_100Mb_hd or \
                self.port_cap.supports_100Mb_fd:
            self.port_cap.max_speed = 100 * 1e6
        elif self.port_cap.supports_10Mb_hd or self.port_cap.supports_10Mb_fd:
            self.port_cap.max_speed = 10 * 1e6
        else:
            self.port_cap.max_speed = 0
        return self.port_cap.max_speed

    def estimate_packets_received_per_sec(self):
        """Estimate the packets received per sec
           as delta_rx_packets/(time since last collection in seconds)"""
        if self.delta_rx_packets == -1:
            return 0
        else:
            return self.delta_rx_packets / self.owner_snapshot.time_since_delta
            #(self.monitoring.collection_epoch_duration * \
            #     self.owner_snapshot.epoch_delta)
        
    def estimate_packets_sent_per_sec(self):
        """Estimate the packets sent per sec
           as delta_tx_packets/(time since last collection in seconds)"""
        if self.delta_tx_packets == -1:
            return 0
        else:
            return self.delta_tx_packets / self.owner_snapshot.time_since_delta
            #(self.monitoring.collection_epoch_duration * \
            #     self.owner_snapshot.epoch_delta)

    def estimate_bits_received_per_sec(self):
        """Estimate the bits received per sec 
           as delta_rx_bits/(time since last collection in seconds)"""
        if self.delta_rx_bytes == -1:
            return 0
        else:
            return (self.delta_rx_bytes*8) / \
                self.owner_snapshot.time_since_delta
            #(self.monitoring.collection_epoch_duration * \
            #     self.owner_snapshot.epoch_delta)

    def estimate_bits_sent_per_sec(self):
        """Estimate the bits sent per sec
           as delta_tx_bits/(time since last collection in seconds)"""
        if self.delta_tx_bytes == -1:
            return 0
        else:
            return (self.delta_tx_bytes*8) / \
                self.owner_snapshot.time_since_delta
            #(self.monitoring.collection_epoch_duration * \
            #     self.owner_snapshot.epoch_delta)

    def estimate_port_rx_utilization(self):
        """Estimate the port rx utilization as 
        [(bits received/s)/max port speed in bits per sec]*100"""
        port_speed_bps = self.port_cap.compute_max_port_speed_bps()
        #self.port_cap[self.port_number].compute_max_port_speed_bps()
        if port_speed_bps > 0:
            return (self.estimate_bits_received_per_sec()/port_speed_bps)*100
        else:
            return 0

    def estimate_port_tx_utilization(self):
        """Estimate the port rx utilization as
        [(bits received/s)/max port speed in bits per sec]*100"""
        port_speed_bps = self.port_cap.compute_max_port_speed_bps()
        #self.port_cap[self.port_number].compute_max_port_speed_bps()    
        if port_speed_bps > 0:
            return (self.estimate_bits_sent_per_sec()/port_speed_bps)*100
        else:
            return 0

    def estimate_avg_port_utilization(self):
        """Estimate the average port utilization."""
        return ( self.estimate_port_rx_utilization()+\
                    self.estimate_port_tx_utilization() )/2.0

class Snapshot:
    """Simple container for storing statistics snapshots for a switch"""
    def __init__(self, monitor_inst):
        self.monitor = monitor_inst
        # Initialize all counters to -1 that way we'll know 
        # whether things have actually been
        # updated. An update gives each counter a value >= 0
        self.dpid = -1 # what switch
        self.collection_epoch = -1 # when collected
        self.time_since_delta = 0
        self.timestamp = -1 # system time stamp
        # spacing between this snapshot and
        # the last collection epoch, should usually be 1 so check
        self.epoch_delta = -1 
        #self.ports_active = -1
        # From aggregate stats - these are point in time counts 
        # i.e. number of flows active "now"
        self.number_of_flows = -1
        self.bytes_in_flows = -1
        self.packets_in_flows = -1
        # Port stats dict - dictionary of per port counters
        self.port_info = dict()
        # Aggregate counters over ALL the ports for a specific switch
        self.total_rx_bytes = -1
        self.total_tx_bytes = -1
        self.total_rx_packets = -1
        self.total_tx_packets = -1
        self.total_rx_packets_dropped = -1
        self.total_tx_packets_dropped = -1
        self.total_rx_errors = -1
        self.total_tx_errors = -1
        # changes in Aggregate switch-level snapshot data since the 
        # last collection epoch
        self.delta_rx_bytes = -1
        self.delta_tx_bytes = -1
        self.delta_rx_packets = -1
        self.delta_tx_packets = -1
        self.delta_rx_packets_dropped = -1
        self.delta_tx_packets_dropped = -1
        self.delta_rx_errors = -1
        self.delta_tx_errors = -1
    
    def to_dict(self):
        dict = {}
        dict['dpid'] = self.dpid
        dict['collection_epoch'] = self.collection_epoch
        dict['timestamp'] = self.timestamp
        dict['time_since_delta'] = self.time_since_delta
        dict['epoch_delta'] = self.epoch_delta
        dict['number_of_flows'] = self.number_of_flows
        dict['bytes_in_flows'] = self.bytes_in_flows
        dict['packets_in_flows'] = self.packets_in_flows
        # Port info
        ports = {}
        for port_num in self.port_info:
            ports[port_num] = self.port_info[port_num].to_dict()
        dict['ports'] = ports
        # Counters
        dict['total_rx_bytes'] = self.total_rx_bytes
        dict['total_tx_bytes'] = self.total_tx_bytes
        dict['total_rx_packets'] = self.total_rx_packets
        dict['total_tx_packets'] = self.total_tx_packets
        dict['total_rx_packets_dropped'] = self.total_rx_packets_dropped
        dict['total_tx_packets_dropped'] = self.total_tx_packets_dropped
        dict['total_rx_errors'] = self.total_rx_errors
        dict['total_tx_errors'] = self.total_tx_errors
        # Deltas
        dict['delta_rx_bytes'] = self.delta_rx_bytes
        dict['delta_tx_bytes'] = self.delta_tx_bytes
        dict['delta_rx_packets'] = self.delta_rx_packets
        dict['delta_tx_packets'] = self.delta_tx_packets
        dict['delta_rx_packets_dropped'] = self.delta_rx_packets_dropped
        dict['delta_tx_packets_dropped'] = self.delta_tx_packets_dropped
        dict['delta_rx_errors'] = self.delta_rx_errors
        dict['delta_tx_errors'] = self.delta_tx_errors
        return dict
    
    def compute_delta_from(self, rhs):
        """Compute the counter and epoch deltas between this 
        snapshot and another (rhs)
        @param rhs - snapshot to compute delta from
        """
        #print "computing delta from snapshot..."
        if self.collection_epoch != rhs.collection_epoch:
            self.epoch_delta = self.collection_epoch - rhs.collection_epoch
            self.time_since_delta = self.timestamp - rhs.timestamp

        self.delta_rx_bytes = max(0, self.total_rx_bytes - rhs.total_rx_bytes)
        self.delta_tx_bytes = max(0, self.total_tx_bytes - rhs.total_tx_bytes)
        self.delta_rx_packets = max(0, \
                                self.total_rx_packets - rhs.total_rx_packets)
        self.delta_tx_packets = max(0, \
                                self.total_tx_packets - rhs.total_tx_packets)
        self.delta_rx_packets_dropped = max(0,\
                                        self.total_rx_packets_dropped - \
                                        rhs.total_rx_packets_dropped)
        self.delta_tx_packets_dropped = max(0,self.total_tx_packets_dropped - \
                                        rhs.total_tx_packets_dropped)
        self.delta_rx_errors = max(0, \
                               self.total_rx_errors - rhs.total_rx_errors)
        self.delta_tx_errors = max(0, \
                                  self.total_tx_errors - rhs.total_tx_errors)
        
        # Send an event to indicate that this switch is having problems
        # when delta_*_packets_dropped or delta_*_errors is > 0?
        # At this point we wouldn't be able to nail down any more
        # specific port info. We could probably let the port delta
        # computation do that. An event/alert at this point 
        # may be a high-level (or wasted)
        # alert if the port delta sends a more specific event as well.
        
        # Compute port deltas
        for key in self.port_info:
            self.port_info[key].compute_delta_from( rhs.port_info[key] )
    
    def store_port_info(self, ports, port_cap):
        """Save per-port counters
        @param ports - collection of port info structures
        @param port_cap - collection of port capacity structures
        """
        self.total_rx_bytes = 0
        self.total_tx_bytes = 0
        self.total_rx_packets = 0
        self.total_tx_packets = 0
        self.total_rx_packets_dropped = 0
        self.total_tx_packets_dropped = 0
        self.total_rx_errors = 0
        self.total_tx_errors = 0

        for item in ports:    
            # Compute all the counter totals
            self.total_rx_bytes += item['rx_bytes']
            self.total_tx_bytes += item['tx_bytes']
            self.total_rx_packets += item['rx_packets']
            self.total_tx_packets += item['tx_packets']
            self.total_rx_packets_dropped += item['rx_dropped']
            self.total_tx_packets_dropped += item['tx_dropped']
            self.total_rx_errors += item['rx_errors']
            self.total_tx_errors += item['tx_errors']
            # Store each item in the ports collection in a port dict
            new_port_info = PortInfo(port_cap[item['port_no']], self.monitor)
            #new_port_info = PortInfo(port_cap)
            new_port_info.owner_snapshot = self
            new_port_info.port_number = item['port_no']
            new_port_info.total_rx_bytes = item['rx_bytes']
            new_port_info.total_tx_bytes = item['tx_bytes']
            new_port_info.total_rx_packets = item['rx_packets']
            new_port_info.total_tx_packets = item['tx_packets']
            new_port_info.total_rx_packets_dropped = item['rx_dropped']
            new_port_info.total_tx_packets_dropped = item['tx_dropped']
            new_port_info.total_rx_errors = item['rx_errors']
            new_port_info.total_tx_errors = item['tx_errors']
            self.port_info[new_port_info.port_number] = new_port_info

    def get_total_rx_bytes(self):
        """Return the total number of bytes received at this switch
           across all its ports."""
        # For each port in the port dict
        # sum the total rx bytes
        return self.total_rx_bytes

    def get_total_tx_bytes(self):
        """Return the total number of bytes transmitted by this switch
           across all its ports."""
        return self.total_tx_bytes

    def ready(self):
        """Indicate whether this snapshot has been filled in with data
        from table, aggregate and port stats replies. A snaphot is not
        ready until all three sets of counter data have been received."""
        # Check whether our delta counters have been filled in
        # If the collection epoch = 1 then we're ready
        if self.collection_epoch == 1:
            return True
        elif self.delta_rx_bytes == -1:
            return False
        elif self.delta_tx_bytes == -1:
            return False
        elif self.delta_rx_packets_dropped == -1:
            return False
        elif self.delta_tx_packets_dropped == -1:
            return False
        elif self.delta_rx_errors == -1:
            return False
        elif self.delta_tx_errors == -1:
            return False
        else: 
            return True

    def print_stats(self):
        """Dump aggregate switch-level and per-port stats to stdout."""
        print "---snap-start---"
        print "dpid                    : 0x%x" % (self.dpid)
        print "collection epoch        : %d" % (self.collection_epoch)
        print "epoch delta             : %d" % (self.epoch_delta)
        print "ports active            : %d" % (len(self.port_info))
        print "# flows                 : %d" % (self.number_of_flows)
        print "# bytes in flows        : %d" % (self.bytes_in_flows)
        print "# packets in flows      : %d" % (self.packets_in_flows)
        print "ttl rx bytes            : %d" % (self.total_rx_bytes)
        print "ttl tx bytes            : %d" % (self.total_tx_bytes)
        print "ttl rx packets          : %d" % (self.total_rx_packets)
        print "ttl tx packets          : %d" % (self.total_tx_packets)
        print "ttl rx packets dropped  : %d" % (self.total_rx_packets_dropped)
        print "ttl tx packets dropped  : %d" % (self.total_tx_packets_dropped)
        print "ttl rx errors           : %d" % (self.total_rx_errors)
        print "ttl tx errors           : %d" % (self.total_tx_errors)
        print "delta rx bytes          : %d" % (self.delta_rx_bytes)
        print "delta tx bytes          : %d" % (self.delta_tx_bytes)
        print "delta rx packets        : %d" % (self.delta_rx_packets)
        print "delta tx packets        : %d" % (self.delta_tx_packets)
        print "delta rx packets dropped: %d" % (self.delta_rx_packets_dropped)
        print "delta tx packets dropped: %d" % (self.delta_tx_packets_dropped)
        print "delta rx errors         : %d" % (self.delta_rx_errors)
        print "delta tx errors         : %d" % (self.delta_tx_errors)
        print "___port info___"
        # Show per-port stats
        for key in self.port_info:
            self.port_info[key].print_stats()
            print "\n"
        print "---snap-end---"

class Monitoring(Component):
    """Class collects switch statistics to annotate topology graph"""
    def __init__(self, ctxt):
        Component.__init__(self, ctxt)
        self.ctxt_ = ctxt
        lg.debug( 'Simple monitoring started!' )
        # We'll keep track of the logical time we've been 
        # collecting data so that we can group snapshots from different
        # switches in the network across time i.e. we want to look 
        # at changes in monitoring data within a single
        # collection epoch as well as across collection epochs
        self.collection_epoch = 0
        # Keep track of the latest collection epoch included in a 
        # stats reply so we know what
        self.max_stats_reply_epoch = -1
        # Keep track of the set of the switches we are monitoring. 
        # As switches join and leave the network we can enable or disable
        # the timers that poll them for their stats
        self.switches = set([])
        # Track the switches that we haven't heard from in a while
        self.silent_switches = set([])
        # Store the snapshots of the switch stats
        # [dpid][<snapshot1>,<snapshot2>,...,<snapshotN>]
        self.snapshots = {}
        # Store the capabilities of each port for each switch
        # [dpid][<port1>,<port2>,...,<portN>
        self.port_cap = {}
        # Pending queries - things we've been asked for but have not yet
        # satisfied
        self.pending_queries = set([])

        # Set defaults
        self.table_stats_poll_period = DEFAULT_POLL_TABLE_STATS_PERIOD
        self.aggregate_stats_poll_period = DEFAULT_POLL_AGGREGATE_STATS_PERIOD
        self.port_stats_poll_period = DEFAULT_POLL_PORT_STATS_PERIOD
        self.collection_epoch_duration = DEFAULT_COLLECTION_EPOCH_DURATION
        self.max_snapshots_per_switch = DEFAULT_MAX_STATS_SNAPSHOTS_PER_SWITCH
        # Grab a handle to the topology (just for testing communicating w/
        # dispatch server
        self.topo = self.ctxt.resolve(topodb)
        # Grab a handle to the dispatch server
        #self.foo = self.ctxt.resolve(Foo)
        self.dispatch = self.ctxt.resolve(DispatchServer)
        if self.dispatch == None:
            lg.debug( "Dispatch Server not available." )
        else: 
            lg.debug( "Dispatch Server available." )
            # Register for switch query events
            #token = self.dispatch.register_for_message_type( "swquery", \
            #                               self.dispatch_message_callback)
            #self.dispatch.deregister_for_message_type( "swquery", token )
            # Register for topology events
            token = self.dispatch.register_for_message_type( "topoquery", \
                                            self.dispatch_topo_query_callback )
            self.dispatch.register_for_message_type( "switchquery", \
                                          self.dispatch_switch_query_callback )
            self.dispatch.register_for_message_type( "toposubsetquery", \
                                         self.dispatch_service_query_callback )
        self.nodesAllowed = self.topo.subset.nodesAllowed

    def dispatch_service_query_callback( self, query ):
        lg.debug( "Got service query from DispatchServer xid: %d" % \
                      (query.xid) )
        # Create new topoquery reply message
        if self.topo.named_subsets.has_key(query.subset_name):
            service = self.topo.named_subsets[query.subset_name]
            #lg.debug( service.__dict__ )
            # Send the topology subset - the receiver needs to know
            # what to do when query.subset_name != "all" because they
            # aren't getting a topo instance instead they get a subset instance
            event = TopologyReplyEvent( query.xid, service, query.subset_name )
            # Post event
            self.post( pyevent( "toporeplyevent", event ) )

    def dispatch_switch_query_callback( self, query ):
        # Get the xid and save to a pending list
        # Issue the "right" kind of message to the target switch with
        # the xid, when the results come back a custom event will be generated
        lg.debug( "got switch query request: %s" % (query.__dict__) )
        # put the xid on the pending_queries list
        if query.query_type == "tablestats":
            lg.debug( "got tablestats query" )
            # Add the xid to pending list
            self.pending_queries.add( query.xid )
            # send off an openflow command
            self.send_table_stats_request( query.dpid, query.xid )
        elif query.query_type == "portstats":
            lg.debug( "got portstats query" )
            self.pending_queries.add( query.xid )
            self.send_port_stats_request( query.dpid, query.xid )
        elif query.query_type == "aggstats":
            lg.debug( "got aggstats query" )
            self.pending_queries.add( query.xid )
            flow = of.ofp_match()
            flow.wildcards = 0xffffffff
            self.send_aggregate_stats_request( query.dpid, \
                                                  flow,  0xff, query.xid )
        elif query.query_type == "latestsnapshot":
            lg.debug( "got latestsnapshot query" )
            # Look at the latest snapshot we have (if any) for this switch
            # and post a custom event
            if query.dpid in self.switches:
                latest_snapshot = self.get_latest_switch_stats(query.dpid)
                if latest_snapshot != None:
                    lg.debug( "Replying to snapshot query" )
                    reply = SwitchQueryReplyEvent( query.xid, query.dpid, \
                                SwitchQueryReplyEvent.QUERY_LATEST_SNAPSHOT,\
                                      latest_snapshot )
                    self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
        elif query.query_type == "flowstats":
            lg.debug( "got flowstats query" )
            self.pending_queries.add( query.xid )
            flow = of.ofp_match()
            flow.wildcards = 0xffffffff
            self.send_flow_stats_request(query.dpid, flow,  0xff, query.xid)
        elif query.query_type == "queuestats":
            lg.debug( "got queuestats query" )
            self.pending_queries.add( query.xid )
            self.send_queue_stats_request(query.dpid, query.xid)
        else:
            lg.debug( "ignoring unexpected query-type: %s" % query.query_type )

    def dispatch_topo_query_callback( self, xid ):
        lg.debug( "Got topo query from DispatchServer xid: %d" % (xid) )
        # Create new topoquery reply message
        event = TopologyReplyEvent( xid, self.topo )
        # Post event
        self.post( pyevent( "toporeplyevent", event ) )

    def dispatch_message_callback( self, message ):
        lg.debug( "Got message from DispatchServer: %s" % (message) )

    def configure(self, conf):
        """Configures the monitoring module using any command-line
        parameters.
        """
        # Use any command-line params to configure ourselves
        # if no command-line params were passed then use defaults
        lg.debug( "Configuring monitoring..." )
        #self.register_python_event( LinkUtilizationReplyEvent.NAME )
        #print conf
        # Set everything to the default values initially
        #self.table_stats_poll_period = DEFAULT_POLL_TABLE_STATS_PERIOD
        #self.aggregate_stats_poll_period = DEFAULT_POLL_AGGREGATE_STATS_PERIOD
        #self.port_stats_poll_period = DEFAULT_POLL_PORT_STATS_PERIOD
        #self.collection_epoch_duration = DEFAULT_COLLECTION_EPOCH_DURATION
        #self.max_snapshots_per_switch = DEFAULT_MAX_STATS_SNAPSHOTS_PER_SWITCH
        
        if 'arguments' in conf:
            args = {}
            for arg in conf['arguments']:
                if '=' in arg:
                    key, value = arg.split('=')
                else:
                    key, value = arg, ''
                args[key] = value
        
            #print args    
            # extract params that "should/could" be there
            if 'table_poll' in args:
                self.table_stats_poll_period = float(args['table_poll'])
            
            if 'port_poll' in args:
                self.port_stats_poll_period = float(args['port_poll'])

            if 'aggregate_poll' in args:
                self.aggregate_stats_poll_period = \
                    float(args['aggregate_poll'])
            
            if 'epoch_duration' in args:
                self.collection_epoch_duration = long(args['epoch_duration'])

            if 'max_snapshots' in args:
                self.max_snapshots_per_switch = long(args['max_snapshots'])


        # Print out our configuration
        lg.debug( "Table poll    : %f" % (self.table_stats_poll_period) )
        lg.debug( "Port poll     : %f" % (self.port_stats_poll_period) )
        lg.debug( "Agg poll      : %f" % (self.aggregate_stats_poll_period) )
        lg.debug( "Epoch length  : %d" % (self.collection_epoch_duration) )
        lg.debug( "Max snapshots : %d" % (self.max_snapshots_per_switch) )

        # Start our logical clock                     
        self.fire_epoch_timer()
        
        # Start some internal debugging
        self.fire_stats_debug_timer()
        self.fire_utilization_broadcasts()
        # Used for testing only
        #self.fire_fake_network_status_events()
        lg.debug( "Finished configuring monitoring" )
        # Add named subsets to topodb from config file
        if self.topo != None:
            self.add_named_topo_views()

    def add_named_topo_views(self):
        # create hash
        #self.topo.named_subsets = {}
        # populate hash - hard coded for now, will use config file later
        self.topo.named_subsets["serviceA"] = \
            Subset(service_A_Nodes, service_A_Hosts)
        self.topo.named_subsets["serviceB"] = \
            Subset(service_B_Nodes, service_B_Hosts)

    def fire_fake_network_status_events(self):
        lg.debug( "sending fake network status events" )
        # Link status changes
        linkAdminDown = LinkAdminDownEvent( -1, 10000, 100, 10001, 101 )
        self.post( pyevent( LinkAdminDownEvent.NAME, linkAdminDown ) )
        
        linkAdminUp = LinkAdminUpEvent( -1, 10000, 100, 10001, 101 )
        self.post( pyevent( LinkAdminUpEvent.NAME, linkAdminUp ) )

        # Switch status changes
        switchAdminDown = SwitchAdminDownEvent( -1, 10000, 0 )
        self.post( pyevent( SwitchAdminDownEvent.NAME, switchAdminDown ) )

        switchAdminUp = SwitchAdminUpEvent( -1, 10000, 0 )
        self.post( pyevent( SwitchAdminUpEvent.NAME, switchAdminUp ) )

        # Node (topology changes)
        nodeEnter = NodeEnterEvent( -1, 10000, 0 )
        self.post( pyevent( NodeEnterEvent.NAME, nodeEnter ) )

        nodeExit = NodeExitEvent( -1, 10000, 0 )
        self.post( pyevent( NodeExitEvent.NAME, nodeExit ) )

        # Port errors and dead/silent switches
        portError = PortErrorEvent( -1, 10000, 100 )
        portError.rx_dropped = 10
        portError.tx_dropped = 11
        portError.rx_errors = 12
        portError.tx_errors = 13
        portError.rx_frame_err = 14
        portError.rx_over_err = 15
        portError.rx_crc_err = 16
        portError.collisions = 17
        self.post( pyevent( PortErrorEvent.NAME, portError ) )

        silentSwitch = SilentSwitchEvent( -1, 10000 )
        self.post( pyevent( SilentSwitchEvent.NAME, silentSwitch ) )

        self.post_callback( 10, self.fire_fake_network_status_events )


    def getInterface(self):
        """Returns an instance of itself."""
        return str(Monitoring)
      
    # Install me - register all the handlers and set up polling timers
    def install(self):
        """ Installs the monitoring component. Register all the event handlers\
        and sets up the switch polling timers."""    
        # Add handlers for the events we're interested in
        #self.register_handler( Flow_in_event.static_get_name(), \
        #                 lambda event: self.handle_flow_in(event))
        self.register_handler( Flow_mod_event.static_get_name(), \
                         lambda event: self.handle_flow_mod(event))
        self.register_handler( Datapath_join_event.static_get_name(), \
                         lambda event: self.handle_datapath_join(event))
        self.register_handler( Datapath_leave_event.static_get_name(), \
                         lambda event: self.handle_datapath_leave(event))
        # Stats reporting events
        self.register_handler( Table_stats_in_event.static_get_name(), \
                         lambda event: self.handle_table_stats_in(event))
        self.register_handler( Port_stats_in_event.static_get_name(), \
                         lambda event: self.handle_port_stats_in(event))
        self.register_handler( Aggregate_stats_in_event.static_get_name(), \
                         lambda event: self.handle_aggregate_stats_in(event))
        self.register_handler( Flow_stats_in_event.static_get_name(), \
                         lambda event: self.handle_flow_stats_in(event))
        self.register_handler( Queue_stats_in_event.static_get_name(), \
                         lambda event: self.handle_queue_stats_in(event))
    
    # Construct and send our own stats request messages so we can make use
    # of the xid field (store our logical clock/collection epoch here) to
    # detect whether stats replies from switches are delayed, lost or
    # re-ordered
    def send_table_stats_request(self, dpid, xid=-1):
        """Send a table stats request to a switch (dpid).
        @param dpid - datapath/switch to contact
        """
        # Build the request and then send a barrier request after it
        # to try to coerce in-order processing.
        # Using flow installer as an example of OF message construction
        # in python
        request = of.ofp_stats_request()
        if xid == -1:
            request.header.xid = c_htonl(long(self.collection_epoch))
        else:
            request.header.xid = c_htonl(xid)
        request.header.type = OFPT_STATS_REQUEST
        request.type = OFPST_TABLE
        request.flags = 0
        request.header.length = len(request.pack())
        #print request.header.__dict__
        #print c_ntohl(request.header.xid)
        #print request.__dict__
        self.send_openflow_command(dpid, request.pack())

    def send_port_stats_request(self, dpid, xid=-1):
        """Send a port stats request to a switch (dpid).
        @param dpid - datapath/switch to contact
        """
        # Build port stats request message
        request = of.ofp_stats_request()
        if xid == -1:
            request.header.xid = c_htonl(long(self.collection_epoch))
        else:
            request.header.xid = c_htonl(xid)
        request.header.type = OFPT_STATS_REQUEST
        request.type = OFPST_PORT
        request.flags = 0
        
        # Need a body for openflow v1.x.x but not for 0.9.x
        # Construct body as a port_stats_request - need something packable
        body = of.ofp_port_stats_request()
        # Get stats on all ports using OFPP_NONE
        body.port_no = OFPP_NONE

        # set request.header.length = sizeof(packed? stats_request)
        #    +sizeof(packet request body?)

        request.header.length = len(request.pack()) + len(body.pack())
        self.send_openflow_command(dpid, request.pack() +  body.pack())

    def send_aggregate_stats_request(self, dpid, match,  table_id, xid=-1):
        """Send an aggregate stats request to a switch (dpid).
        @param dpid - datapath/switch to contact
        @param match - ofp_match structure
        @param table_id - table to query
        """
        # Create the stats request header
        request = of.ofp_stats_request()
        if xid == -1:
            request.header.xid = c_htonl(long(self.collection_epoch))
        else:
            request.header.xid = c_htonl(xid)
        request.header.type = OFPT_STATS_REQUEST
        request.type = OFPST_AGGREGATE
        request.flags = 0
        # Create the stats request body
        body = of.ofp_aggregate_stats_request()
        body.match = match
        body.table_id = table_id
        body.out_port = OFPP_NONE
        #print request.__dict__
        #print body.__dict__
        #print body.pack()
        # Set the header length
        request.header.length = len(request.pack()) + len(body.pack())
        self.send_openflow_command(dpid, request.pack() + body.pack())

    def send_flow_stats_request(self, dpid, match, table_id, xid=-1):
        """Send a flow stats request to a switch (dpid).
        @param dpid - datapath/switch to contact                               
        @param match - ofp_match structure                                     
        @param table_id - table to query 
        """
        # Create the stats request header
        request = of.ofp_stats_request()
        if xid == -1:
            request.header.xid = c_htonl(long(self.collection_epoch))
        else:
            request.header.xid = c_htonl(xid)
        
        lg.debug( "sending flow stats request xid: %d" % \
                      (c_htonl(request.header.xid)) )
        request.header.type = OFPT_STATS_REQUEST
        request.type = OFPST_FLOW
        request.flags = 0
        # Create the stats request body
        body = of.ofp_flow_stats_request()
        body.match = match
        body.table_id = table_id
        body.out_port = OFPP_NONE
        #lg.debug( request.__dict__ )
        #lg.debug( body.__dict__ )
        request.header.length = len(request.pack()) + len(body.pack())
        self.send_openflow_command(dpid, request.pack() + body.pack())

    def send_queue_stats_request(self, dpid, xid=-1):
        lg.debug( "sending queue stats request" )
        """Send a queue stats request to a switch (dpid). 
        @param dpid - datapath/switch to contact
        """
        # Create the stats request header 
        request = of.ofp_stats_request()
        if xid == -1:
            request.header.xid = c_htonl(long(self.collection_epoch))
        else:
            request.header.xid = c_htonl(xid)
        request.header.type = OFPT_STATS_REQUEST
        request.type = OFPST_QUEUE
        request.flags = 0
        # Create the stats request body
        body = of.ofp_queue_stats_request()
        body.port_no = OFPP_ALL
        body.queue_id = OFPQ_ALL
        request.header.length = len(request.pack()) + len(body.pack())
        self.send_openflow_command(dpid, request.pack() + body.pack())

    # Command API
    def count_silent_switches(self):
        """Count the number of switches that have not responded to stats
           requests."""
        return len(self.silent_switches)

    def get_all_silent_switches(self):
        """Return the set of switches that have not responded to stats
           requests."""
        return self.silent_switches

    def get_all_switch_stats(self, dpid):
        """API call to get all the recent readings of switch stats
        @param dpid - datapath/switch snapshots to return
        """
        if dpid in self.switches:
            return self.snapshots[dpid]
        else: 
            return {}

    def get_max_stats_reply_epoch(self):
        """API call to return the latest epoch for which we have at
        least 1 switch stats reply"""
        return self.max_stats_reply_epoch

    def get_latest_port_gbps(self, time_consistent=True):
        port_utilizations = []
        # Look at the latest reply epoch
        # For each switch get any snapshot that is ready with
        # collected for the latest reply epoch
        # Go through that snapshot and pull out the port
        # info
        # Create portutilization instance: 
        # [dpid,port,gbps_transmitted,gbps_received]
        for dpid in self.switches:
            # Get the latest snapshot for each switch
            latest_snapshot = self.get_latest_switch_stats(dpid)
            # If there's a recent snapshot see if it's ready (complete)
            # AND for the most recent collection epoch
            if latest_snapshot != None and latest_snapshot.ready(): 
                #lg.debug( "found latest snapshot for dpid 0x%x" % (dpid) )
                # If we want the snapshots to all be from the same 
                # most recent collection epoch then ignore the ones that aren't
                if time_consistent and (latest_snapshot.collection_epoch != \
                        self.max_stats_reply_epoch):
                    #lg.debug( "Consistent time required, skipping snaphost" )
                    continue
                    
                #if latest_snapshot.ready() and \
                        #latest_snapshot.collection_epoch\
                        #== self.max_stats_reply_epoch:
                    # Now go thru the snapshot's port info and
                    # create port utilization instances and
                    # add them to the list
                for port in latest_snapshot.port_info:
                    portinfo = latest_snapshot.port_info[port]
                    port_util = PortUtilization()
                    port_util.dpid = dpid
                    port_util.port = portinfo.port_number
                    if not FAKE_BPS_FROM_PKTS:
                        port_util.gbps_transmitted = \
                            portinfo.estimate_bits_sent_per_sec()/1e9
                        port_util.gbps_received = \
                            portinfo.estimate_bits_received_per_sec()/1e9
                    else:
                        port_util.gbps_transmitted = AVG_PKT_SIZE * \
                            portinfo.estimate_packets_sent_per_sec()
                        port_util.gbps_received = AVG_PKT_SIZE * \
                            portinfo.estimate_packets_received_per_sec()
                    port_utilizations.append(port_util)
            else:
                pass

        for util in port_utilizations:
            if util.gbps_transmitted > 0.5 or util.gbps_received > 0.5:
                lg.debug(util.__dict__)

        return port_utilizations

    def get_latest_switch_stats(self, dpid):
        """API call to get the latest stats snapshot for a switch
        @param dpid - datapath/switch snapshot to return
        """
        if dpid not in self.switches:
            return None

        switch_stats_q = self.snapshots[dpid]
        if len(switch_stats_q) > 0: 
            return switch_stats_q[0]
        else:
            return None

    def get_all_port_capabilities(self, dpid):
        """API call to get all the port capabilities for a switch
        @param dpid - datapath/switch port capabilities to return
        """
        if dpid not in self.port_cap:
            return None
        else:
            return self.port_cap[dpid]
    
    def get_port_capabilities(self, dpid, port_num):
        """API call to get the capabilities of a specific port for a switch
        @param dpid - datapath/switch to get capabilities for
        @param port_num - specific port to get capabilities for
        """
        if dpid not in self.port_cap:
            return None
        else: 
            return (self.port_cap[dpid])[port_num]

    #def get_flow_stats(self, dpid, flow_spec):
    #    """API call to get stats of a specific flow from a switch"""
    #    return {}

    #def get_flow_stats_on_path(self, dpid_list, flow_spec):
    #    """API call to get stats of a specific flow from a set of switches"""
    #    return {}

    # Timers
    # Stats debugging timer
    def fire_stats_debug_timer(self):
        lg.debug( "stats debugging" )
        self.get_latest_port_gbps()
        # re-post timer at some multiple of the collection epoch
        self.post_callback( self.collection_epoch_duration*2, \
                                self.fire_stats_debug_timer )

    def fire_utilization_broadcasts(self):
        #lg.debug( "utilization broadcasts" )
        port_utils = self.get_latest_port_gbps()
        # Set xid = -1 when its unsolicited
        event = LinkUtilizationReplyEvent( -1, port_utils )
        # Post event
        self.post( pyevent( LinkUtilizationReplyEvent.NAME, event ) )
        self.post_callback( 0.1, self.fire_utilization_broadcasts )

    # Logical clock timer    
    def fire_epoch_timer(self):
        """Handler updates the logical clock used by Monitoring."""        
        # Print the silent switch list
        lg.debug( "---silent switches start at epoch: %d---" \
                       % (self.collection_epoch) )
        for dpid in self.silent_switches:
            lg.debug( dpid )
            if self.topo.all_connected():
                self.topo.setNodeFaultStatus(dpid, True)
            # Publish an event for each silent switch
            silentSwitch = SilentSwitchEvent( -1, dpid )
            self.post( pyevent( SilentSwitchEvent.NAME, silentSwitch ) )
        lg.debug( "---silent switches end at epoch: %d---" \
                       % (self.collection_epoch))

        # Add all switches to the silent list at the start of every
        # epoch. We'll remove them as they reply to stats requests
        for dpid in self.switches:
            if dpid not in self.silent_switches:
                #self.topo.setNodeFaultStatus(dpid, False)
                self.silent_switches.add(dpid)

        # Update the epoch
        self.collection_epoch += 1
        lg.debug( "updated clock: %d" % (self.collection_epoch) )
        self.post_callback( self.collection_epoch_duration, \
                                self.fire_epoch_timer )
        
    def dump_stats(self):
        """Print out the latest swtich stats."""
        lg.debug( "%d switches being monitored" % (len(self.switches)) )
        # for each switch, dump the lastest snapshot
        for dpid in self.switches:
            switch_stats_q = self.snapshots[dpid]
            latest_snapshot = switch_stats_q[0]
            if latest_snapshot.ready():
                latest_snapshot.print_stats()
            #else:
                #print "no snapshots ready"

    # Table stats timer
    def fire_table_stats_timer(self, dpid):
        """Handler polls a swtich for its table stats.
        @param dpid - datapath/switch to contact
        """
        #print "firing table stats timer. \
        #collection epoch: {0:d}".format(self.collection_epoch)    
        # Send a message and renew timer (if the switch is still around)       
        if dpid in self.switches:
            # Send a table stats request
            #self.ctxt.send_table_stats_request(dpid)    
            self.send_table_stats_request(dpid)    
            self.post_callback(self.table_stats_poll_period, \
                       lambda : self.fire_table_stats_timer(dpid))

    # Port stats timer
    def fire_port_stats_timer(self, dpid):
        """Handler polls a switch for its port stats.
        @param dpid - datapath/switch to contact
        """
        # print "firing port stats timer. \
        # collection epoch: {0:d}".format(self.collection_epoch)
        # Send a ports stats message and renew timer 
        # (if the switch is still around)
        if dpid in self.switches:
            #self.ctxt.send_port_stats_request(dpid)
            self.send_port_stats_request(dpid)    
            self.post_callback(self.port_stats_poll_period, \
                        lambda :  self.fire_port_stats_timer(dpid))

    # Aggregate stats timer    
    def fire_aggregate_stats_timer(self, dpid):
        """Handler polls a switch for its aggregate stats.
        @param dpid - datapath/switch to contact
        """
        # print "firing aggregate stats timer. \
        # collection epoch: {0:d}".format(self.collection_epoch)
        # Send a message and renew timer (if the switch is still around)
        if dpid in self.switches:
            # Grab data for all flows
            flow = of.ofp_match() 
            flow.wildcards = 0xffffffff
            self.send_aggregate_stats_request(dpid, flow,  0xff)    
            self.post_callback(self.aggregate_stats_poll_period, \
                        lambda :  self.fire_aggregate_stats_timer(dpid))

    def fire_flow_stats_timer(self, dpid):
        """
        Handler polls a switch for its aggregate stats.
        @param dpid - datapath/switch to contact
        """
        if dpid in self.switches:
            # Grab data for all flows
            flow = of.ofp_match()
            flow.wildcards = 0xffffffff
            self.send_flow_stats_request(dpid, flow,  0xff)
            self.post_callback(10, lambda : self.fire_flow_stats_timer(dpid))
    
    def fire_queue_stats_timer(self, dpid):
        """
        Handler polls a switch for its queue stats.
        @param dpid - datapath/switch to contact
        """
        if dpid in self.switches:
            self.send_queue_stats_request(dpid)
            self.post_callback(10, lambda : self.fire_queue_stats_timer(dpid))
        
    # Event handlers. FYI if you need/want to find out what fields exist 
    # in a specific event type look at src/nox/lib/util.py at the utility 
    # functions that are used to manipulate them
    def handle_flow_in(self, event):
        """Handler responds to flow_in events.
        @param event - flow in event to handle
        """
        #lg.debug( 'Handling flow in event' )
        return CONTINUE

    def handle_flow_mod(self, event):
        """Handler responds to flow_in modification events.
        @param flow mod event to handle
        """
        #lg.debug( 'Handling flow mod event.' )
        #print event.__dict__
        return CONTINUE
    
    def handle_datapath_join(self, event):
        """Handler responds to switch join events.
        @param event datapath/switch join event to handle
        """
        # grab the dpid from the event
        dpid = event.datapath_id
        epoch = self.collection_epoch
        #lg.debug( "updated clock: %d" % (self.collection_epoch) )

        #lg.debug( "Handling switch join. Epoch: {0:d},dpid: {1:x}"\
        #                                        .format(epoch,dpid) )
        #print "collection epoch {0:d} handling dp join.\
        # dpid: {1:x}".format(epoch,dpid)    
        #print current_thread()        
        #print event.__dict__

        #ports = event.ports
        #for item in ports:
            # Figure out what speeds are supported
            #port_enabled = (item['config'] & openflow.OFPPC_PORT_DOWN) == 0
            #link_enabled = (item['state'] & openflow.OFPPS_LINK_DOWN) == 0
            # Look at features supported, advertised and curr(ent)
            #supports_10MB_HD = (item['curr'] & openflow.OFPPF_10MB_HD) == \
            #                                         openflow.OFPPF_10MB_HD
            #supports_10MB_FD = (item['curr'] & openflow.OFPPF_10MB_FD) > 0
            #supports_100MB_HD = (item['curr'] & openflow.OFPPF_100MB_HD) > 0
            #supports_100MB_FD = (item['curr'] & openflow.OFPPF_100MB_FD) == \
            #                                          openflow.OFPPF_100MB_FD
            #supports_1GB_HD = (item['curr'] & openflow.OFPPF_1GB_HD) > 0
            #supports_1GB_FD = (item['curr'] & openflow.OFPPF_1GB_FD) > 0
            #supports_10GB_FD = (item['curr'] & openflow.OFPPF_10GB_FD) > 0
            
            #print '\t', item['name'],item['port_no'],item['speed'], \
            #item['curr'], port_enabled, link_enabled, supports_10MB_FD, \
            #supports_100MB_FD, supports_1GB_FD, supports_10GB_FD
            
        # Set up some timers for polling this switch periodically
        # Whenever a new switch joins set up some timers for polling it 
        # for its stats (using the monitor.py example as a rough reference)
        if not dpid in self.switches and (not self.nodesAllowed or \
                                          dpid in self.nodesAllowed):
            lg.debug( "Handling switch join. Epoch: %d, dpid: 0x%x" % \
                       (epoch,dpid) )
            # Add this switch to the set of switches being monitored
            self.switches.add(dpid)
            # Create an entry to store its stats snapshots
            self.snapshots[dpid] = deque()
            # Create an entry to store its port capabilities
            self.port_cap[dpid] = dict()
            # Add ports
            ports = event.ports
            for item in ports:
                # create port capability
                new_port_cap = PortCapability()
                # set fields
                #print "port capability"
                #print item
                new_port_cap.port_name = item['name']
                new_port_cap.port_number = item['port_no']
                new_port_cap.port_enabled = ((item['config'] & \
                                             openflow.OFPPC_PORT_DOWN) == 0)
                new_port_cap.link_enabled = (item['state'] & \
                                             openflow.OFPPS_LINK_DOWN) == 0
                new_port_cap.supports_10Mb_hd = (item['curr'] & \
                                                openflow.OFPPF_10MB_HD) == \
                                                openflow.OFPPF_10MB_HD
                new_port_cap.supports_10Mb_fd = (item['curr'] & \
                                                 openflow.OFPPF_10MB_FD) > 0
                new_port_cap.supports_100Mb_hd = (item['curr'] & \
                                                  openflow.OFPPF_100MB_HD) > 0
                new_port_cap.supports_100Mb_fd = (item['curr'] & \
                                                  openflow.OFPPF_100MB_FD) == \
                                                  openflow.OFPPF_100MB_FD
                new_port_cap.supports_1Gb_hd = (item['curr'] & \
                                                openflow.OFPPF_1GB_HD) > 0
                new_port_cap.supports_1Gb_fd = (item['curr'] & \
                                                openflow.OFPPF_1GB_FD) > 0
                new_port_cap.supports_10Gb_fd = (item['curr'] & \
                                                openflow.OFPPF_10GB_FD) > 0
                # Have the port capability instance compute the
                # max port speed
                new_port_cap.compute_max_port_speed_bps()
                # store the port capability instance to the port map/dict
                (self.port_cap[dpid])[new_port_cap.port_number]=new_port_cap
            
            # Set up timers            
            self.post_callback(self.table_stats_poll_period, \
                         lambda : self.fire_table_stats_timer(dpid))
            self.post_callback(self.port_stats_poll_period, \
                         lambda :  self.fire_port_stats_timer(dpid))
            self.post_callback(self.aggregate_stats_poll_period, \
                         lambda :  self.fire_aggregate_stats_timer(dpid))
            # Testing flow stats requests
            #self.post_callback(10, lambda : self.fire_flow_stats_timer(dpid))
            #self.post_callback(10, lambda : self.fire_queue_stats_timer(dpid))
            #print self.snapshots
        
        # Mark switch as silent until we get a stats reply from it
        if dpid not in self.silent_switches:
            self.silent_switches.add(dpid)

        return CONTINUE

    def handle_datapath_leave(self, event):
        """Handler responds to switch leave events.
        @param event - datapath leave event to handle
        """
        dpid = event.datapath_id
        #lg.debug( "Handling dp leave. dpid: {0:x}".format(dpid) )
        lg.debug( "Handling switch leave. Epoch: %d, dpid: 0x%x" % \
                                              (self.collection_epoch, dpid) )
        # drop all the stats for this switch
        if dpid in self.switches:
            #print "removing switch"
            self.switches.remove(dpid)
            # Throw away its stats snapshots
            del self.snapshots[dpid]

        # Remove switch from the slient_switch list if it's currently on it
        if dpid in self.silent_switches:
            self.silent_switches.remove(dpid)
            
        return CONTINUE

    # Handlers for switch stats events
    def handle_aggregate_stats_in(self, event):
        """Handler responds to receiving aggregate switch stats.
        @param event - aggregate stats in event to handle
        """
        
        #lg.debug( event.__dict__ )
        # Get the snapshot list
        dpid = event.datapath_id
        # Use the xid as the current collection epoch
        current_collection_epoch = event.xid #self.collection_epoch

        if event.xid in self.pending_queries:
            lg.debug( "responding to switch query for aggregate stats" )
            # Publish custom event
            reply = SwitchQueryReplyEvent( event.xid, event.datapath_id, \
                                       SwitchQueryReplyEvent.QUERY_AGG_STATS,\
                                       event )
            self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
            # Remove the xid from our todo list
            self.pending_queries.remove( event.xid )


        # Check whether this stats reply pushes forward out notion of   
        # "latest" 
        #if current_collection_epoch > self.max_stats_reply_epoch:
        #    self.max_stats_reply_epoch = current_collection_epoch

        #lg.debug( "handling agg stats in." )
        #print event.__dict__
        
        # Remove switch from silent_switch list if it's on it
        if dpid in self.silent_switches:
            self.silent_switches.remove(dpid)

        # Get the deque holding our snapshots
        try:
            switch_stats_q = self.snapshots[dpid]

            # Are we adding a new snapshot?    
            if len(switch_stats_q) == 0:
                # Create new snapshot and save it
                #print "creating new snapshot"
                new_snapshot = Snapshot( self )
                # Set the collection epoch and the datapath id
                new_snapshot.collection_epoch = current_collection_epoch
                new_snapshot.timestamp = time.time()
                new_snapshot.dpid = dpid
                new_snapshot.number_of_flows = event.flow_count
                new_snapshot.bytes_in_flows = event.byte_count
                new_snapshot.packets_in_flows = event.packet_count
                # Always add the most recent snapshot to the front of the queue
                switch_stats_q.appendleft(new_snapshot)
            else:
                pass #print "possibly updating existing snapshot"
            
            # Get the latest snapshot
            latest_snapshot = switch_stats_q[0]

            # If it's for this collection epoch, just update it/overwrite it
            if latest_snapshot.collection_epoch == current_collection_epoch:
                #print "updating existing snapshot"
                latest_snapshot.timestamp = time.time()
                latest_snapshot.number_of_flows = event.flow_count
                latest_snapshot.bytes_in_flows = event.byte_count
                latest_snapshot.packets_in_flows = event.packet_count
            else:
                # Only add a new snapshot if it's later in time
                # than the "latest" snapshot
                if current_collection_epoch > latest_snapshot.collection_epoch:
                    #print "adding a new snapshot"
                    new_snapshot = Snapshot( self )
                    new_snapshot.collection_epoch = current_collection_epoch
                    new_snapshot.timestamp = time.time()
                    new_snapshot.dpid = dpid
                    new_snapshot.number_of_flows = event.flow_count
                    new_snapshot.bytes_in_flows = event.byte_count
                    new_snapshot.packets_in_flows = event.packet_count
                    # Calculate any deltas from the latest snapshot
                    new_snapshot.epoch_delta = current_collection_epoch - \
                        latest_snapshot.collection_epoch
                    # Always add the most recent snapshot to the front 
                    # of the queue
                    switch_stats_q.appendleft(new_snapshot)
                    # Limit the number of old snapshots we keep around        
                    if len(switch_stats_q) > self.max_snapshots_per_switch:
                         #lg.debug( "Purging old stats. \
                         #     dpid: {0:x}".format(dpid) )
                        switch_stats_q.pop()
                else:
                    # Received delayed snapshot
                    #lg.debug( """Received delayed snapshot from past
                    #epoch: %d, when the latest collection epoch is: %d""" % \
                    #(current_collection_epoch, \
                    #     latest_snapshot.collection_epoch))
                    pass
        except Exception:
            pass
        finally:        
            pass #self.dump_stats()

        return CONTINUE

    def handle_table_stats_in(self, event):
        """Handle receipt of table stats from a switch.
        @param event - table stats event to handle
        """
        dpid = event.datapath_id
        
        #lg.debug( event.__dict__ )

        if event.xid in self.pending_queries:
            lg.debug( "responding to switch query for table stats" )
            # Publish custom event
            reply = SwitchQueryReplyEvent( event.xid, event.datapath_id, \
                                      SwitchQueryReplyEvent.QUERY_TABLE_STATS,\
                                      event )
            self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
            # Remove the xid from our todo list
            self.pending_queries.remove( event.xid )

        # Remove switch from silent_switch list if it's on it 
        if dpid in self.silent_switches:
            self.silent_switches.remove(dpid)

        #lg.debug( "Handling table stats in from dpid: %x" % (dpid) )
        #print event.__dict__        
        tables = event.tables
        return CONTINUE

    def handle_port_stats_in(self, event):
        """Handle receipt of port stats from a switch.
        @param event - port stats event to handle
        """
        dpid = event.datapath_id

        if event.xid in self.pending_queries:
            lg.debug( "responding to switch query for port stats" )
            # Publish custom event
            reply = SwitchQueryReplyEvent( event.xid, event.datapath_id, \
                                      SwitchQueryReplyEvent.QUERY_PORT_STATS,\
                                      event )
            self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
            # Remove the xid from our todo list
            self.pending_queries.remove( event.xid )


        # Use the reply xid as the current collection epoch
        current_collection_epoch = event.xid #self.collection_epoch
        #lg.debug( "Handling port stats in from dpid: %x" % (dpid) )
        #print event.ports

        # Check whether this stats reply pushes forward out notion of
        # "latest"
        if current_collection_epoch > self.max_stats_reply_epoch:
            self.max_stats_reply_epoch = current_collection_epoch

        # Remove switch from silent_switch list if it's on it
        if dpid in self.silent_switches:
            self.silent_switches.remove(dpid)
            self.topo.setNodeFaultStatus(dpid, False)

        ports = event.ports
        try:            
            switch_stats_q = self.snapshots[dpid]

            # Are we adding a new snapshot?    
            if len(switch_stats_q) == 0:
                # Create new snapshot and save it
                # print "creating new snapshot"
                new_snapshot = Snapshot( self )
                # Set the collection epoch and the datapath id
                new_snapshot.collection_epoch = current_collection_epoch
                new_snapshot.timestamp = time.time()                
                new_snapshot.dpid = dpid
                new_snapshot.store_port_info(ports, self.port_cap[dpid])
                # Always add the most recent snapshot to the front of the queue
                switch_stats_q.appendleft(new_snapshot)
            else:
                pass #print "possibly updating existing snapshot"
            
            # Get the latest snapshot
            latest_snapshot = switch_stats_q[0]

            # If the latest snapshot is for this collection epoch, just 
            # update it
            if latest_snapshot.collection_epoch == current_collection_epoch:
                #print "updating existing snapshot"
                latest_snapshot.timestamp = time.time()
                latest_snapshot.store_port_info(ports, self.port_cap[dpid])
                # update deltas if we can
                if len(switch_stats_q) > 1:
                    previous_snapshot = switch_stats_q[1]
                    latest_snapshot.compute_delta_from(previous_snapshot)
            else:
                # Only add a new snapshot if it's more recent
                # than the collection epoch of the "latest" snapshot
                if current_collection_epoch > latest_snapshot.collection_epoch:
                    #print "adding a new snapshot"
                    new_snapshot = Snapshot( self )
                    new_snapshot.collection_epoch = current_collection_epoch
                    new_snapshot.timestamp = time.time()
                    #new_snapshot.ports_active = ports_active
                    new_snapshot.dpid = dpid
                    # store port info
                    new_snapshot.store_port_info(ports, self.port_cap[dpid])
                    # Compute deltas from the previous snapshot
                    new_snapshot.compute_delta_from(latest_snapshot)
                    # Always add the most recent snapshot to the 
                    # front of the queue
                    switch_stats_q.appendleft(new_snapshot)
                    # Limit the number of old snapshots we keep around        
                    if len(switch_stats_q) > self.max_snapshots_per_switch:
                    #lg.debug( "Purging old stats. dpid: {0:x}".format(dpid) )
                        switch_stats_q.pop()
                else:
                    # Received delayed snapshot
                    #lg.debug( """Received delayed snapshot from past epoch: %d,
                    #when the latest collection epoch is: %d""" % \
                    #(current_collection_epoch, \
                    #     latest_snapshot.collection_epoch))
                    pass
        except Exception:
            pass
        finally:        
            pass
        return CONTINUE

    def handle_flow_stats_in(self, event):
        #lg.debug( "handling flow stats in: %s" % (event.__dict__) ) 

        if event.xid in self.pending_queries:
            lg.debug( "responding to switch query for flow stats" )
            # Publish custom event
            reply = SwitchQueryReplyEvent( event.xid, event.datapath_id, \
                               SwitchQueryReplyEvent.QUERY_FLOW_STATS, event )
            self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
            # Remove the xid from our todo list
            self.pending_queries.remove( event.xid )

        return CONTINUE

    def handle_queue_stats_in(self,event):
        lg.debug( "handle queue stats in: %s" % (event.__dict__) )
        
        if event.xid in self.pending_queries:
            lg.debug( "responding to switch query for queue stats" )
            # Publish custom event
            reply = SwitchQueryReplyEvent( event.xid, event.datapath_id, \
                               SwitchQueryReplyEvent.QUERY_QUEUE_STATS, event )
            self.post( pyevent( SwitchQueryReplyEvent.NAME, reply ) )
            # Remove the xid from our todo list
            self.pending_queries.remove( event.xid )

        return CONTINUE

def getFactory():
    """Returns an object able to create monitoring instances."""
    class Factory:
        """A class able to create monitoring instances."""
        def instance(self, ctxt):
            """Returns a/the monitoring instance."""
            return Monitoring(ctxt)

    return Factory()
