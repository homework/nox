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

#include <boost/shared_ptr.hpp>

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

/* HWDB */
extern "C" {
#include "/home/homeuser/hwdb/srpc.h"
#include "/home/homeuser/hwdb/config.h"
#include "/home/homeuser/hwdb/rtab.h"
}

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


  struct nw_hdr {
    struct ether_header *ether;
    struct iphdr *ip;
    union {
      struct udphdr *udp;
      struct tcphdr *tcp;
      struct igmphdr *igmp;
    };
    uint8_t *data;
  };

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
     * return a simple hello string in order to test the connectivity
     * with the python code
     */
    std::string hello_world();

    /**
     * a method to get the current dhcp mappings.
     *
     * \return a vector of string that describe each mapping.
     */
    std::vector<std::string> get_dhcp_mapping(); 

    /**
     * register the proxy class between the c++ module and the python module. 
     * useful in order to have bidirectional communication.
     */
    void register_proxy(applications::dhcp_proxy  *proxy);
    
    /**
     * a method to revoke the right to a host with the specific ethernet address
     * to connect to the network. 
     */
    void revoke_mac_access(const ethernetaddr& ether); 

    /**
     * a method to revoke access to a host on the level of the physical layer. 
     */
    void blacklist_mac(ethernetaddr& ether);

    /**
     * a method to revoke access to a host on the level of the physical layer. 
     */
    std::vector<std::string> get_blacklist_status();

    /**
     * a method to remove a mac address from the blacklist mac address list
     */
    void whitelist_mac(const ethernetaddr& ether);
  private:
    size_t generate_dhcp_reply(uint8_t **buf, struct dhcp_packet  *dhcp, 
			       uint16_t dhcp_len, Flow *flow, uint32_t send_ip, 
			       uint8_t dhcp_msg_type, uint32_t lease);
    void refresh_default_flows();
    ipaddr select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type, uint32_t requested_ip) ;
    bool check_access(const ethernetaddr& ether);
    bool ip_matching(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip);
    bool is_ip_broadcast(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip);
    bool is_ip_host(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip);
    bool is_ip_router (const ipaddr& subnet, uint32_t netmask,const ipaddr& ip);
    uint32_t find_free_ip(const ipaddr& subnet, int netmask);
    bool add_addr(uint32_t ip);
    bool del_addr(uint32_t ip);
    bool extract_headers(uint8_t*, uint32_t, vigil::nw_hdr*);
    void insert_hwdb(const char *action, const char *ip, const char *mac, const char *hostname);

    bool send_flow_modification (Flow fl, uint32_t wildcard, datapathid datapath_id,
				 uint32_t buffer_id, uint16_t command,
				 uint16_t idle_timeout, 
				 std::vector<boost::shared_array<char> > act);

    //a pointer to the proxy of the module
    applications::dhcp_proxy *p_dhcp_proxy;

    //datapath storage
    std::vector<datapathid*> registered_datapath;

    //store blacklisted mac addresses -> this might need to persist over reboots.
    std::set<ethernetaddr> mac_blacklist;

    //store blacklisted mac addresses -> this might need to persist over reboots.
    std::map<ipaddr, std::set<ipaddr> > multicast_ip;

    //storage of the ip to mac translation throught the dhcp protocol 
    std::map<struct ethernetaddr, struct dhcp_mapping *> mac_mapping;    
    std::map<struct ipaddr, struct dhcp_mapping *> ip_mapping;

    //the mac address of the bridge
    ethernetaddr bridge_mac;

	/* HWDB */
	RpcConnection rpc;

    //netlink control  
    struct nl_sock *sk;        //the socket to talk to netlink
    int ifindex;               //index of the interface. TODO: not sure if this change if 
                               // interfaces go up and down. 
  };
}

#endif
