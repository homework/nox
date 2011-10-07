/* Copyright 2008 (C) Nicira, Inc.
 * Copyright 2009 (C) Stanford University.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef homework_routing_HH
#define homework_routing_HH
#include "event.hh"

#include "component.hh"
#include "config.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include <vector>
#include <map>
#include <utility>
#include <set>

#include <net/ethernet.h>  
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>   
#include <linux/netlink.h> 
#include <netlink/netlink.h>
#include <netlink/object-api.h>
#include <linux/pkt_sched.h>
#include <netlink/addr.h>
#include <netlink/route/link.h> 
#include <netlink/route/addr.h> 
#include <netlink/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
      
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/igmp.h>


#include "netinet++/datapathid.hh"
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ipaddr.hh"
#include "netinet++/cidr.hh"

#include "dhcp_proxy.hh"
#include "homework_dhcp/homework_dhcp.hh"

// extern "C" {
// #include <hwdb/srpc.h>
// #include <hwdb/rtab.h>
// #include <hwdb/config.h>
// }

namespace vigil
{
  using namespace std;
  using namespace vigil::container;
  
  class homework_dhcp;


  /** \brief homework_routing
   * \ingroup noxcomponents
   * 
   * @author
   * @date
   */
  class homework_routing
      : public Component 
  {
      public:
          /** \brief Constructor of homework_routing.
           *
           * @param c context
           * @param node XML configuration (JSON object)
           */
          homework_routing(const Context* c, const json_object* node)
              : Component(c)
          {}

          /** \brief Configure homework_routing.
           * 
           * Parse the configuration, register event handlers, and
           * resolve any dependencies.
           *
           * @param c configuration
           */
          void configure(const Configuration* c);

          /** \brief Start homework_routing.
           * 
           * Start the component. For example, if any threads require
           * starting, do it now.
           */
          void install();

          /** \brief Get instance of homework_routing.
           * @param c context
           * @param component reference to component
           */
          static void getInstance(const container::Context* c, 
                  homework_routing*& component);

          /**
           * \brief dhcp packet handler
           *
           * A generic handler for packet_in events. This hopefully 
           * will mature latter to more specific functionality.
           */
          Disposition arp_handler(const Event& e);
          Disposition packet_in_handler(const Event& e);
          Disposition pae_handler(const Event& e);
          Disposition mac_pkt_handler(const Event& e);
          Disposition igmp_handler(const Event& e);

          /**
           * \brief check when new switches join
           *
           * required in order to get a list of registered switches
           */
          Disposition datapath_join_handler(const Event& e);

          /**
           * \brief check when switches leave
           *
           * required in order to get a list of registered switches
           */
          Disposition datapath_leave_handler(const Event& e);

          /**
           * a method to revoke the right to a host with the specific ethernet address
           * to connect to the network. 
           */
          void revoke_mac_access(const ethernetaddr& ether); 

          /**
           * a method to revoke access to a host on the level of the physical layer. 
           */
          void blacklist_mac(const ethernetaddr& ether);

          /**
           * a method to revoke access to a host on the level of the physical layer. 
           */
          std::vector<std::string> get_blacklist_status();
          void whitelist_mac(const ethernetaddr& ether);
          bool send_flow_modification (Flow fl, uint32_t wildcard, datapathid datapath_id,
                  uint32_t buffer_id, uint16_t command,
                  uint16_t idle_timeout, uint16_t prio,
                  std::vector<boost::shared_array<char> > act);
          std::vector<std::string> get_dhcp_mapping();
           bool check_access(const ethernetaddr& ether);
           Disposition device_handler(const Event& e);

      private:
           void permit_mac(const ethernetaddr& ether);

          bool extract_headers(uint8_t *data, uint32_t data_len, struct nw_hdr *hdr);
          //a pointer to the proxy of the module
//          dhcp_proxy *p_dhcp_proxy;
          homework_dhcp *p_dhcp;
          //netmasks
          cidr_ipaddr routable, non_routable, multicast, init_subnet;

          ethernetaddr bridge_mac;
          //datapath storage
          std::vector<datapathid*> registered_datapath;

          //store blacklisted mac addresses -> this might need to persist over reboots.
          std::map<ipaddr, std::set<ipaddr> > multicast_ip;

          //store blacklisted mac addresses -> this might need to persist over reboots.
          std::set<ethernetaddr> mac_blacklist;
          //store permitted mac addreses
          std::set<ethernetaddr> mac_permit;
  };
}

#endif
