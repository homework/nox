#include "homework_dhcp.hh"

#include <map>
#include <utility>

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>

#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "vlog.hh"

#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"
#include "netinet++/ipaddr.hh"

const char *dhcp_msg_type_name[] = {NULL, "DHCPDiscover", "DHCPOffer", 
                    "DHCPRequest", "DHCPDecline", "DHCPAck", 
                    "DHCPNak", "DHCPRelease", "DHCPInform"};
#define BRIDGE_INTERFACE_NAME "br0"

#define MAX_ROUTABLE_LEASE 1800
#define MAX_NON_ROUTABLE_LEASE 30

#define ROUTABLE_SUBNET "10.2.0.0"
#define ROUTABLE_NETMASK 16

#define NON_ROUTABLE_SUBNET "10.3.0.0"
#define NON_ROUTABLE_NETMASK 16

#define MULTICAST_SUBNET "224.0.0.0"
#define MULTICAST_NETMASK 4

#define INIT_SUBNET "10.4.0.0"
#define INIT_NETMASK 16


namespace vigil
{
    static Vlog_module lg("homework_dhcp");

    void homework_dhcp::configure(const Configuration* c) {
        lg.dbg(" Configure called ");

        resolve(p_routing);

        this->routable = cidr_ipaddr(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK);
        this->non_routable = cidr_ipaddr(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK);
        this->init_subnet = cidr_ipaddr(ipaddr(INIT_SUBNET), INIT_NETMASK); 
        this->multicast = cidr_ipaddr(ipaddr(MULTICAST_SUBNET), MULTICAST_NETMASK);
    }

    void homework_dhcp::install() {
        /*HWDB*/
        unsigned char addr[ETH_ALEN];
        const char *host;
        unsigned short port;
        const char *service;
        host = HWDB_SERVER_ADDR;
        port = HWDB_SERVER_PORT;
        service = "HWDB";
        int s;
        struct ifreq ifr;
        struct nl_cache *cache;

        //initialiaze and connect the socket to the netlink socket
        if((this->sk = nl_socket_alloc()) == NULL) {
            perror("socket alloc");
            exit(1);
        }
        if(nl_connect(sk, NETLINK_ROUTE) != 0) {
            perror("nl connect");
            exit(1);
        }

        //looking the index of the bridge  
        if ( (rtnl_link_alloc_cache(sk, &cache) ) != 0) {
            perror("link alloc cache");
            exit(1);
        }

        if ( ( this->ifindex = rtnl_link_name2i(cache,  BRIDGE_INTERFACE_NAME) ) == 0) {
            perror("Failed to translate interface name to int");
            exit(1);
        }
        printf("Retrieving ix %d for intf %s\n", this->ifindex, BRIDGE_INTERFACE_NAME);

       register_handler<Packet_in_event>(boost::bind(&homework_dhcp::dhcp_handler, 
                    this, _1));
        register_handler<Datapath_join_event>(boost::bind(&homework_dhcp::datapath_join_handler, 
                    this, _1));
        register_handler<Datapath_leave_event>(boost::bind(&homework_dhcp::datapath_leave_handler, 
                    this, _1));

        rpc = NULL;
        if (!rpc_init(0)) {
            fprintf(stderr, "Failure to initialize rpc system\n");
            return;
        }
        if (!(rpc = rpc_connect(const_cast<char *>(host), port, const_cast<char *>(service), 1l))) {
            fprintf(stderr, "Failure to connect to HWDB at %s:%05u\n", host, port);
            return;
        }

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s==-1) {
            perror("Failed to open socket");
            exit(1);
        }

        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, BRIDGE_INTERFACE_NAME, sizeof(BRIDGE_INTERFACE_NAME));

        if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
            perror("Failed to get mac address");
            exit(1);
        }    
        memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        this->bridge_mac = ethernetaddr(addr);
        printf("br0 mac addr : %s\n", this->bridge_mac.string().c_str());
        close(s);

        lg.dbg(" Install called ");
    }

    void homework_dhcp::insert_hwdb(const char *action, const char *ip, 
            const char *mac, const char *hostname) {

        char q[SOCK_RECV_BUF_LEN], r[SOCK_RECV_BUF_LEN];
        unsigned int rlen = 0;

        char stsmsg[RTAB_MSG_MAX_LENGTH];

        unsigned int bytes;

        if (!rpc) {
            fprintf(stderr, "Error: not connected to HWDB.\n");
            return;
        }

        bytes = 0;
        memset(q, 0, SOCK_RECV_BUF_LEN);
        bytes += sprintf(q + bytes, "SQL:insert into Leases values (" );
        /* action */
        bytes += sprintf(q + bytes, "\"%s\", ", action);
        /* mac address */
        bytes += sprintf(q + bytes, "\"%s\", ", mac);
        /* ip address */
        bytes += sprintf(q + bytes, "\"%s\", ", ip);
        /* hostname (optional) */
        bytes += sprintf(q + bytes, "\"%s\")\n",hostname);

        fprintf(stderr, "%s", q);
        if (! rpc_call(rpc, q, bytes, r, sizeof(r), &rlen)) {
            fprintf(stderr, "rpc_call() failed\n");
            return;
        }
        r[rlen] = '\0';
        if (rtab_status(r, stsmsg))
            fprintf(stderr, "RPC error: %s\n", stsmsg);
    }

    /////////////////////////////////////
    //   Datapath event handling
    /////////////////////////////////////

    /*
     * datapath_join_handler(const Event& e)
     *
     * A function to install all required flow to forward traffic to the controller when 
     * a new controller appears on the network.
     * */
    Disposition homework_dhcp::datapath_join_handler(const Event& e) {
        const Datapath_join_event& pi = assert_cast<const Datapath_join_event&>(e);
        printf("joining switch with datapath id : %s\n", pi.datapath_id.string().c_str());
        this->registered_datapath.push_back( new datapathid(pi.datapath_id));

        std::vector<boost::shared_array<char> > act;
        Flow flow;
        struct ofp_action_output *ofp_act_out;
        uint32_t wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST);
        boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
        act.push_back(ofp_out);
        ofp_act_out=(struct ofp_action_output *)ofp_out.get();

        ofp_act_out->type = htons(OFPAT_OUTPUT);
        ofp_act_out->len = htons(sizeof(struct ofp_action_output));
        ofp_act_out->port = htons(OFPP_CONTROLLER); 
        ofp_act_out->max_len = htons(2000);

        //force to forward dhcp traffic to the controller
        wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST); 
        flow.dl_type = ethernet::IP;
        flow.nw_proto = ip_::proto::UDP;
        flow.tp_src = htons(68);
        flow.tp_dst = htons(67);  
        this->p_routing->send_flow_modification (flow, wildcard, pi.datapath_id,
                -1, OFPFC_ADD, OFP_FLOW_PERMANENT, act);

        return CONTINUE;
    }

    Disposition homework_dhcp::datapath_leave_handler(const Event& e) {
        const Datapath_leave_event& pi = assert_cast<const Datapath_leave_event&>(e);
        printf("leaving switch with datapath id : %s\n", pi.datapath_id.string().c_str());
        vector<datapathid *>::iterator it;
        for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
            if(pi.datapath_id == (const datapathid& )(**it)) {
                delete *it;
                this->registered_datapath.erase(it);
                break;
            }
        }
        return CONTINUE;
    }

    Disposition homework_dhcp::dhcp_handler(const Event& e) {
        const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
        Flow flow(pi.in_port, *(pi.get_buffer()));
        // for some reason events are only fired for this action when nox 
        // sees udp traffic. 
        if( (flow.dl_type != ethernet::IP) ||
                (flow.nw_proto != ip_::proto::UDP) ||
                (ntohs(flow.tp_dst) != 67) || 
                (ntohs(flow.tp_src) != 68)) {
            return CONTINUE;
        }  

        uint8_t *data = pi.get_buffer()->data(), *reply = NULL;
        int32_t data_len = pi.get_buffer()->size();
        int pointer = 0;

        struct nw_hdr hdr;
        if(!this->extract_headers(data, data_len, &hdr)) {
            lg.err("malformed dhcp packet");
        }
        uint16_t dhcp_len = ntohs(hdr.udp->len) - sizeof(struct udphdr);

        //printf("header size:%d\n",  (hdr.data - data));

        pointer = (hdr.data - data);
        data_len -= (hdr.data - data);

        struct dhcp_packet *dhcp = (struct dhcp_packet  *)hdr.data;

        //analyse options and reply respectively.
        data_len -= sizeof(struct dhcp_packet);
        pointer +=  sizeof(struct dhcp_packet);

        //get the exact message type of the dhcp request
        uint8_t dhcp_msg_type = 0;
        uint32_t requested_ip = dhcp->ciaddr;
        while(data_len > 2) {
            uint8_t dhcp_option = data[pointer];
            uint8_t dhcp_option_len = data[pointer+1];

            if(dhcp_option == 0xff) {
                //printf("Got end of options!!!!\n");
                break;
            } else if(dhcp_option == 53) {
                dhcp_msg_type = data[pointer + 2];
                if((dhcp_msg_type <1) || (dhcp_msg_type > 8)) {
                    printf("Invalid DHCP Message Type : %d\n", dhcp_msg_type);
                    return STOP;
                } 
            }else if(dhcp_option == 50) {
                memcpy(&requested_ip, data + pointer + 2, 4);
                struct in_addr in;
                in.s_addr = requested_ip;
                printf("requested ip : %s\n", inet_ntoa(in));
            }

            data_len -=(2 + dhcp_option_len );
            pointer +=(2 + dhcp_option_len );
        }

        if(dhcp_msg_type == DHCPINFORM) {
            return STOP;
        } else if(dhcp_msg_type == DHCPDECLINE){
            return STOP;
        }

        //Must create a fucntion that chooses this ip for the state of the DHCP server. 
        ipaddr send_ip = this->select_ip(ethernetaddr(hdr.ether->ether_shost), dhcp_msg_type, 
                ntohl(requested_ip));
        bool is_routable = (this->routable.matches(send_ip) || this->init_subnet.matches(send_ip)); 
        //ip_matching(ipaddr(ROUTABLE_SUBNET),ROUTABLE_NETMASK, ntohl((uint32_t)send_ip))||
        //(this->ip_matching(ipaddr(INIT_SUBNET),INIT_NETMASK, ntohl((uint32_t)send_ip))));
        bool is_init = this->init_subnet.matches(send_ip);

        //TODO: if ip is routable, add ip to the interface
        if(is_routable) {
            this->add_addr(ntohl((uint32_t)send_ip) + 1);
        } else {
            printf("ip %s is not routable\n", send_ip.string().c_str());
        }

        uint8_t reply_msg_type = (dhcp_msg_type == DHCPDISCOVER?DHCPOFFER:DHCPACK);

        if( (requested_ip != 0)  &&
                ((dhcp_msg_type == DHCPREQUEST) && 
                 (requested_ip != (uint32_t)send_ip))){
            struct in_addr in;
            in.s_addr = send_ip;
            printf("DHCPNACK: requested ip differ from send_ip %s\n", inet_ntoa(in));
            reply_msg_type = DHCPNAK;
            send_ip = requested_ip;
        }
        size_t len = 
            generate_dhcp_reply(&reply, dhcp, dhcp_len, &flow, ntohl((uint32_t)send_ip), reply_msg_type, 
                    (is_routable&& !is_init)?MAX_ROUTABLE_LEASE:MAX_NON_ROUTABLE_LEASE);

        insert_hwdb("add", send_ip.string().c_str(), flow.dl_src.string().c_str(), "NULL");

        send_openflow_packet(pi.datapath_id, Array_buffer(reply, len), 
                OFPP_IN_PORT, pi.in_port, 1);
        return STOP;
    }

    uint32_t homework_dhcp::find_free_ip(const ipaddr& subnet, int netmask) {
        map<struct ipaddr, struct dhcp_mapping *>::iterator iter_ip;
        timeval tv; 
        uint32_t inc = 4;
        uint32_t ip = ntohl((const uint32_t)subnet);
        ethernetaddr ether = ethernetaddr();

        gettimeofday(&tv, NULL);
        for (;(ip&(0xFFFFFFFF<<netmask))==ntohl(subnet);ip += inc) {
            if((iter_ip = this->ip_mapping.find(ipaddr(ip + 1))) == this->ip_mapping.end()) 
                break;

            //if the lease has ended for less than 5 minutes then keep the mapping just in case
            if( tv.tv_sec - iter_ip->second->lease_end < 5*60 )
                continue;

            //if everything above passed then we have to invalidate this mapping and keep the ip addr
            if(iter_ip->second != NULL) {
                ether = iter_ip->second->mac;
                delete iter_ip->second;
            }
            this->ip_mapping.erase(ip + 1);
            if(this->mac_mapping.find(ether) != this->mac_mapping.end()) {
                this->mac_mapping.erase(ether);
            }
            break;
        }

        //run out of availiable ip
        if((ip&(0xFFFFFFFF<<netmask))!=ntohl(subnet)) {
            return 0; //return zero if no availiable ip found
        }
        return ip;
    }

    ipaddr homework_dhcp::select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type, 
            uint32_t requested_ip) {
        map<struct ethernetaddr, struct dhcp_mapping *>::iterator iter_ether;
        struct dhcp_mapping *state;
        //bool is_routable;
        uint32_t ip = 0;
        timeval tv;
        time_t lease_end = 0;

        gettimeofday(&tv, NULL);
        lease_end = tv.tv_sec;

        printf("looking mac %s with dhcp msg type : (%d) %s\n", 
                ether.string().c_str(), dhcp_msg_type, dhcp_msg_type_name[dhcp_msg_type]);

        //firstly check if the mac address is aloud access
        //is_routable = this->check_access(ether); 
        //lease_end +=(is_routable)?MAX_ROUTABLE_LEASE:MAX_NON_ROUTABLE_LEASE;
        lease_end +=MAX_ROUTABLE_LEASE;
        //printf("is_routable: %s\n", (is_routable)?"True":"False");

        //check now if we can find the MAC in the list 
        if( ((iter_ether = this->mac_mapping.find(ether)) != this-> mac_mapping.end()) &&
                (iter_ether->second != NULL)) {
            state = iter_ether->second;
            ip = ntohl(state->ip);
            state->lease_end = lease_end;
        } else {
            ip = find_free_ip(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK);
            if(!ip) {
                printf("run out of ip's - no reply\n");
                return STOP;
            }
            ip++;

            //create state with new ip and send it out.
            printf("lease end:%ld %ld\n",  tv.tv_sec, lease_end);
            // state = new dhcp_mapping(ipaddr(ip), ether, lease_end, 
            //                   is_routable?DHCP_STATE_FINAL:DHCP_STATE_INIT);
            state = new dhcp_mapping(ipaddr(ip), ether, lease_end, DHCP_STATE_FINAL);
            printf("inserting new entry for %s - %s\n", ether.string().c_str(), 
                    state->string().c_str());
            this->mac_mapping[ether] = state;
            this->ip_mapping[ipaddr(ip)] = state;
            //I need to find here the appropriate ip addr
        } 
        return ipaddr(ip);
    }

    void homework_dhcp::getInstance(const Context* c,
            homework_dhcp*& component) {
        component = dynamic_cast<homework_dhcp*>
            (c->get_by_interface(container::Interface_description
                                 (typeid(homework_dhcp).name())));
    }

    std::vector<std::string> 
        homework_dhcp::get_dhcp_mapping() { 
            std::map<struct ethernetaddr, struct dhcp_mapping *>::iterator iter = 
                this->mac_mapping.begin();
            std::vector<std::string> v;
            for (; iter != this->mac_mapping.end(); iter++) {
                if(iter->second == NULL) continue;
                v.push_back(iter->second->string()); 
            }
            return v;
        };

    /////////////////////////////////////////////
    //   Netlink interaction methods
    ////////////////////////////////////////////
    bool homework_dhcp::add_addr(uint32_t ip) {
        struct rtnl_addr *addr;
        struct nl_addr *local_addr;

        // Allocate an empty address object to be filled out with the attributes
        // of the new address.
        addr = rtnl_addr_alloc();
        if(addr == NULL) {
            perror("addr alloc");
            return 1;
        }

        // Fill out the mandatory attributes of the new address. Setting the
        // local address will automatically set the address family and the
        // prefix length to the correct values.
        rtnl_addr_set_ifindex(addr, this->ifindex);
        ip = htonl(ip);
        if((local_addr = nl_addr_build(AF_INET, &ip, 4)) == NULL) {
            perror("addr parse");
            exit(1);
        }
        nl_addr_set_prefixlen(local_addr, 30);
        char tmp[1024];
        nl_addr2str (local_addr, tmp, 1024);
        printf("setting ip %s on intf br0(%d)\n", tmp, this->ifindex);
        if(rtnl_addr_set_local(addr, local_addr) != 0) {
            perror("addr_set_local");
            exit(1);
        }

        // Build the netlink message and send it to the kernel, the operation will
        // block until the operation has been completed. Alternatively the required
        // netlink message can be built using rtnl_addr_build_add_request() to be
        // sent out using nl_send_auto_complete().
        int ret = rtnl_addr_add(this->sk, addr, 0);
        if( (ret < 0) && ( abs(ret) != NLE_EXIST)) {
            nl_perror(ret, "addr_set_local");
            exit(1);
        }
        return 1;
        // Free the memory
        //nl_addr_destroy(local_addr);
        rtnl_addr_put(addr);    
    }

    bool homework_dhcp::del_addr(uint32_t ip) {
        struct rtnl_addr *addr;
        struct nl_addr *local_addr;

        // Allocate an empty address object to be filled out with the attributes
        // of the new address.
        addr = rtnl_addr_alloc();
        if(addr == NULL) {
            perror("addr alloc");
            return 1;
        }

        // Fill out the mandatory attributes of the new address. Setting the
        // local address will automatically set the address family and the
        // prefix length to the correct values.
        rtnl_addr_set_ifindex(addr, this->ifindex);
        ip = htonl(ip);
        if((local_addr = nl_addr_build(AF_INET, &ip, 4)) == NULL) {
            perror("addr parse");
            exit(1);
        }
        nl_addr_set_prefixlen(local_addr, 30);
        char tmp[1024];
        nl_addr2str (local_addr, tmp, 1024);
        printf("setting ip %s on intf br0(%d)\n", tmp, this->ifindex);
        if(rtnl_addr_set_local(addr, local_addr) != 0) {
            perror("addr_set_local");
            exit(1);
        }

        // Build the netlink message and send it to the kernel, the operation will
        // block until the operation has been completed. Alternatively the required
        // netlink message can be built using rtnl_addr_build_add_request() to be
        // sent out using nl_send_auto_complete().
        int ret = rtnl_addr_delete(sk, addr, 0);
        if( (ret < 0) && ( abs(ret) != NLE_EXIST)) {
            nl_perror(ret, "addr_set_local");
            exit(1);
        }
        return 1;
        // Free the memory
        //nl_addr_destroy(local_addr);
        rtnl_addr_put(addr);    
    }

    size_t homework_dhcp::generate_dhcp_reply(uint8_t **ret, struct dhcp_packet  * dhcp, 
            uint16_t dhcp_len, Flow *flow, uint32_t send_ip,
            uint8_t dhcp_msg_type, uint32_t lease) {
        //uint8_t *ret = NULL;
        int len =  sizeof( struct ether_header) + sizeof(struct iphdr) + 
            sizeof(struct udphdr) + sizeof(struct dhcp_packet) + 3
            + 6 + 6 + 6 + 6 + 6 + 1;

        //message_type + netmask + router + nameserver + lease_time + end option
        //lease time is seconds since it will timeout

        //allocate space for he dhcp reply
        *ret = new uint8_t[len];
        bzero(*ret, len);

        //setting up ethernet header details
        struct ether_header *ether = (struct ether_header *) *ret;
        ether->ether_type = htons(ETHERTYPE_IP);
        memcpy(ether->ether_dhost, (const uint8_t *)flow->dl_src, ETH_ALEN);
        memcpy(ether->ether_shost,  (const uint8_t *)this->bridge_mac, ETH_ALEN);

        //setting up ip header details   
        struct iphdr *ip = (struct iphdr *) (*ret + sizeof(struct ether_header));
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0; 
        ip->tot_len = htons(len - sizeof(struct ether_header));
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 0x80;
        ip->protocol = 0x11;
        ip->saddr =   htonl(send_ip + 1); 
        ip->daddr =  inet_addr("255.255.255.255");
        ip->check = ip_::checksum(ip, 20);

        //setting up udp header details   
        struct udphdr *udp = (struct udphdr *)(*ret + sizeof(struct ether_header) + 
                sizeof(struct iphdr));
        udp->source = htons(67);
        udp->dest = htons(68);
        udp->len = htons(len - sizeof(struct ether_header) - sizeof(struct iphdr));
        udp->check = 0x0;

        struct dhcp_packet  *reply = 
            (struct dhcp_packet *)(*ret + sizeof(struct ether_header) + 
                    sizeof(struct iphdr) + sizeof(struct udphdr));
        reply->op = BOOTREPLY;
        reply->htype = 0x01;
        reply->hlen = 0x6;
        reply->xid = dhcp->xid;
        if(dhcp_msg_type != DHCPNAK) { 
            reply->yiaddr = (uint32_t)htonl(send_ip);
            reply->siaddr =  (uint32_t)htonl(send_ip + 1);
        }
        memcpy(reply->chaddr, (const uint8_t *)flow->dl_src, 6);
        reply->cookie =  dhcp->cookie;

        //setting up options
        uint8_t *options = (uint8_t *)(*ret + sizeof(struct ether_header) + 
                sizeof(struct iphdr) +sizeof(struct udphdr) + 
                sizeof(struct dhcp_packet));

        //setting up dhcp msg type
        options[0] = 53;
        options[1] = 1;
        options[2] = dhcp_msg_type;
        options += 3;

        //netmask 
        options[0] = 1;
        options[1] = 4;
        *((uint32_t *)(options + 2)) = htonl(0xFFFFFFFC); 
        options += 6;
        //lease_time
        options[0] = 51;
        options[1] = 4;
        *((uint32_t *)(options + 2)) = htonl(lease); 
        options += 6;
        // if this is a NAK, we don't need to set the other fields
        if((dhcp_msg_type == DHCPNAK) || this->non_routable.matches(send_ip)) {
            //                ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, ipaddr(send_ip))) { 
            options[0] = 0xff; 
            return len;
        }
        //router 
        options[0] = 3;
        options[1] = 4;
        *((uint32_t *)(options + 2)) = htonl(send_ip+1); 
        options += 6;
        //nameserver
        options[0] = 6;
        options[1] = 4;
        *((uint32_t *)(options + 2)) = htonl(send_ip+1); 
        options += 6;
        //router 
        options[0] = 54;
        options[1] = 4;
        *((uint32_t *)(options + 2)) = htonl(send_ip+1); 
        options += 6;
        //set end of options
        options[0] = 0xff;
        return len;
        }

        bool homework_dhcp::extract_headers(uint8_t *data, uint32_t data_len, struct nw_hdr *hdr) {
            uint32_t pointer = 0;

            if(data_len < sizeof( struct ether_header))
                return false;

            // parse ethernet header
            hdr->ether = (struct ether_header *) data;
            pointer += sizeof( struct ether_header);
            data_len -=  sizeof( struct ether_header);

            // parse ip header
            if(data_len < sizeof(struct iphdr))
                return false;
            hdr->ip = (struct iphdr *) (data + pointer);
            if(data_len < hdr->ip->ihl*4) 
                return false;
            pointer += hdr->ip->ihl*4;
            data_len -= hdr->ip->ihl*4;

            //parse udp header
            if(hdr->ip->protocol == ip_::proto::UDP) {
                hdr->udp = (struct udphdr *)(data + pointer);
                hdr->data = data + pointer + sizeof(struct udphdr);    
            } else if(hdr->ip->protocol == ip_::proto::TCP) {
                hdr->tcp = (struct tcphdr *)(data + pointer);
                hdr->data = data + pointer + (hdr->tcp->doff*4);
            } else if(hdr->ip->protocol == ip_::proto::IGMP) {
                hdr->igmp = (struct igmphdr *)(data + pointer);
            } else {
                return false;
            }
            return true;
        }

        REGISTER_COMPONENT(Simple_component_factory<homework_dhcp>,
                homework_dhcp);
    } // vigil namespace
