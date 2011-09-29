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
#ifndef homework_dhcp_HH
#define homework_dhcp_HH
#include <map>

#include "component.hh"
#include "config.h"
#include "dhcp_msg.hh"
#include "hwdb/control.hh"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

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


#include <netinet++/ip.hh>
#include <netinet++/cidr.hh>

#include <boost/shared_ptr.hpp>

namespace vigil
{
    using namespace std;
    using namespace vigil::container;
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

    struct dhcp_mapping;

    /** \brief homework_dhcp
     * \ingroup noxcomponents
     *
     * @author
     * @date
     */
    class homework_dhcp
        : public Component
    {
        public:
            /** \brief Constructor of homework_dhcp.
             *
             * @param c context
             * @param node XML configuration (JSON object)
             */
            homework_dhcp(const Context* c, const json_object* node)
                : Component(c)
            {}

            /** \brief Configure homework_dhcp.
             *
             * Parse the configuration, register event handlers, and
             * resolve any dependencies.
             *
             * @param c configuration
             */
            void configure(const Configuration* c);

            /** \brief Start homework_dhcp.
             *
             * Start the component. For example, if any threads require
             * starting, do it now.
             */
            void install();

            /**
             * \brief dhcp packet handler
             *
             * A generic handler for packet_in events. This hopefully
             * will mature latter to more specific functionality.
             */
            Disposition dhcp_handler(const Event& e);

            /**
             * a method to get the current dhcp mappings.
             *
             * \return a vector of string that describe each mapping.
             */
            std::vector<std::string> get_dhcp_mapping();

            /** \brief Get instance of homework_dhcp.
             * @param c context
             * @param component reference to component
             */
            static void getInstance(const container::Context* c,
                    homework_dhcp*& component);

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
            ethernetaddr get_mac(ipaddr);

            bool is_valid_mapping(ipaddr ip, ethernetaddr mac);
            void clean_leases();
        private:
            bool send_flow_modification (Flow fl, uint32_t wildcard, datapathid datapath_id,
                    uint32_t buffer_id, uint16_t command,
                    uint16_t idle_timeout, uint16_t prio,
                    std::vector<boost::shared_array<char> > act);

            //datapath storage
            std::vector<datapathid*> registered_datapath;
            void insert_hwdb(const char *action, const char *ip, const char *mac,
                    const char *hostname);

            bool add_addr(uint32_t ip);
            bool del_addr(uint32_t ip);
            ipaddr select_ip(const ethernetaddr&, uint8_t, uint32_t) ;
            bool extract_headers(uint8_t *, uint32_t, struct nw_hdr *);
            size_t generate_dhcp_reply(uint8_t **ret, struct dhcp_packet  * dhcp,
                    uint16_t dhcp_len, Flow *flow, uint32_t send_ip,
                    uint8_t dhcp_msg_type, uint32_t lease);

            //storage of the ip to mac translation throught the dhcp protocol
            std::map<struct ethernetaddr, struct dhcp_mapping *> mac_mapping;
            std::map<struct ipaddr, struct dhcp_mapping *> ip_mapping;

            uint32_t find_free_ip(const ipaddr& subnet, int netmask);
            //netmasks
            cidr_ipaddr routable;

            /* HWDB */
            HWDBControl *hwdb;

            //netlink control
            struct nl_sock *sk;        //the socket to talk to netlink
            int ifindex;               //index of the interface.

            // TODO: not sure if this change if
            // interfaces go up and down.
            ethernetaddr bridge_mac;
    };
}

#endif
