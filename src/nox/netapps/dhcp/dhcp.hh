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
#ifndef dhcp_HH
#define dhcp_HH

#include <vector>
#include <map>
#include <utility>

#include <net/ethernet.h>  
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>   
#include <linux/netlink.h> 
#include <netlink/netlink.h>
#include <netlink/object-api.h>
#include <linux/pkt_sched.h>
#include <netlink-types.h> 
#include <netlink/addr.h>
#include <netlink/route/link.h> 
#include <netlink/route/addr.h> 
#include <netlink/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "component.hh"
#include "netinet++/datapathid.hh"
#include "config.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include "dhcp_msg.hh"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ipaddr.hh"

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

#define ARPHRD_ETHER 1


namespace vigil
{

  namespace applications {
    class dhcp_proxy;
  };

  using namespace std;
  using namespace vigil::container;

struct arphdr {
  uint16_t ar_hrd;                       /* format of hardware address   */
  uint16_t ar_pro;                       /* format of protocol address   */
  uint8_t ar_hln;                         /* length of hardware address   */
  uint8_t ar_pln;                         /* length of protocol address   */
  uint16_t ar_op;                        /* ARP opcode (command)         */
  uint8_t ar_sha[ETH_ALEN];     /* sender hardware address      */
  uint32_t ar_sip;                       /* sender IP address            */
  uint8_t ar_tha[ETH_ALEN];     /* target hardware address      */
  uint32_t ar_tip;                       /* target IP address            */
}__attribute__ ((__packed__));




  /** \brief dhcp
   * \ingroup noxcomponents
   * 
   * @author
   * @date
   */
  class dhcp
    : public Component 
  {
  public:
    /** \brief Constructor of dhcp.
     *
     * @param c context
     * @param node XML configuration (JSON object)
     */
    dhcp(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Configure dhcp.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start dhcp.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of dhcp.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    dhcp*& component);
    
    /**
     * \brief dhcp packet handler
     *
     * A generic handler for packet_in events. This hopefully 
     * will mature latter to more specific functionality.
     */
    Disposition dhcp_handler(const Event& e);


    /**
     * \brief dhcp packet handler
     *
     * A generic handler for packet_in events. This hopefully 
     * will mature latter to more specific functionality.
     */
    Disposition arp_handler(const Event& e);
    Disposition packet_in_handler(const Event& e);

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
    
    std::string hello_world();
    std::vector<std::string> get_dhcp_mapping(); 
    void register_proxy(applications::dhcp_proxy  *proxy);

    void revoke_mac_access(const ethernetaddr& ether); 
  private:
    size_t generate_dhcp_reply(uint8_t **buf, struct dhcp_packet  *dhcp, 
			       uint16_t dhcp_len, Flow *flow, uint32_t send_ip, 
			       uint8_t dhcp_msg_type, uint32_t lease);
    void refresh_default_flows();
    ipaddr select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type) ;
    bool check_access(const ethernetaddr& ether);
    bool ip_matching(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip);
    uint32_t find_free_ip(const ipaddr& subnet, int netmask);
    bool add_addr(uint32_t ip);
    bool del_addr(uint32_t ip);

    //a pointer to the proxy of the module
    applications::dhcp_proxy *p_dhcp_proxy;

    //datapath storage
    std::vector<datapathid*> registered_datapath;

    //storage of the ip to mac translation throught the dhcp protocol 
    std::map<struct ethernetaddr, struct dhcp_mapping *> mac_mapping;    
    std::map<struct ipaddr, struct dhcp_mapping *> ip_mapping;

    ethernetaddr bridge_mac;

    //netlink control  
    struct nl_sock *sk;              //
    int ifindex;                              //index of the interface. TODO: not sure if this change if 
                                                    // interfaces go up and down. 

  };
}

#endif
