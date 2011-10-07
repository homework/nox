#include "homework_routing.hh"
#include "dhcp_proxy.hh"

#include <map>
#include <utility>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>

#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"

//#include "homework_dhcp/dhcp_mapping.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"
#include "netinet++/ipaddr.hh"

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

#define MAX_IP_LEN 32

#define FLOW_TIMEOUT_DURATION 10


namespace vigil
{
    static Vlog_module lg("homework_routing");

    void homework_routing::configure(const Configuration* c) 
    {
        lg.dbg(" Configure called ");
        this->routable = cidr_ipaddr(ipaddr(ROUTABLE_SUBNET), 
                                     ROUTABLE_NETMASK);
        this->non_routable = cidr_ipaddr(ipaddr(NON_ROUTABLE_SUBNET), 
                                         NON_ROUTABLE_NETMASK);
        this->init_subnet = cidr_ipaddr(ipaddr(INIT_SUBNET), 
                                        INIT_NETMASK); 
        this->multicast = cidr_ipaddr(ipaddr(MULTICAST_SUBNET), 
                                      MULTICAST_NETMASK); 
    }

    void homework_routing::install()
    {
        lg.dbg(" Install called ");
        unsigned char addr[ETH_ALEN];
        struct ifreq ifr;
        int s;
        //struct nl_cache *cache;
        /*HWDB*/
        const char *host;
        unsigned short port;
        const char *service;
        host = HWDB_SERVER_ADDR;
        port = HWDB_SERVER_PORT;
        service = "HWDB";

        register_handler<Packet_in_event>(boost::bind(&homework_routing::mac_pkt_handler, 
                                                      this, _1));
        register_handler<Datapath_join_event>(boost::bind(&homework_routing::datapath_join_handler, 
                                                          this, _1));
        register_handler<Datapath_leave_event>(boost::bind(&homework_routing::datapath_leave_handler, 
                                                           this, _1));
        register_handler<HWDBEvent>(boost::bind(&homework_routing::device_handler, 
                                                this, _1));

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s==-1) {
            perror("Failed to open socket");
            exit(1);
        }

        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, BRIDGE_INTERFACE_NAME, sizeof(BRIDGE_INTERFACE_NAME));

        if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
            lg.err("Failed to get mac address");
            exit(1);
        }    
        memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        this->bridge_mac = ethernetaddr(addr);
        lg.info("br0 mac addr : %s", this->bridge_mac.string().c_str());
        close(s);

        this->resolve(p_dhcp);
    }

    Disposition homework_routing::device_handler(const Event& e) {
        lg.err("homework_routing event received.\n");
        const HWDBEvent& event = assert_cast<const HWDBEvent&>(e);

        for (list<HWDBDevice>::const_iterator i = event.devices.begin();
             i != event.devices.end(); i++) {

            HWDBDevice d = *i;
            lg.info("%s\t%s\n", d.mac, d.action);

            if(strcmp(d.action, "permit") == 0) {
                this->permit_mac(ethernetaddr(string(d.mac)));
            } else if (strcmp(d.action, "blacklist") == 0) {
                this->blacklist_mac(ethernetaddr(string(d.mac)));
            } else if(strcmp(d.action, "deny") == 0) {
                this->whitelist_mac(ethernetaddr(string(d.mac)));
            }
        }
        return CONTINUE;

    }
    /////////////////////////////////////
    //   Datapath event handling
    /////////////////////////////////////
    Disposition homework_routing::datapath_join_handler(const Event& e) {
        const Datapath_join_event& pi = assert_cast<const Datapath_join_event&>(e);
        lg.info("joining switch with datapath id : %s", pi.datapath_id.string().c_str());
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

        //force to forward igmp traffic to controller. 
        flow.dl_type = ethernet::IP;
        flow.nw_proto = ip_::proto::IGMP;
        wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO);   
        this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                      -1, OFPFC_ADD,OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY, act);
        return CONTINUE;
    }

    Disposition homework_routing::datapath_leave_handler(const Event& e) {
        const Datapath_leave_event& pi = assert_cast<const Datapath_leave_event&>(e);
        lg.err("leaving switch with datapath id : %s", pi.datapath_id.string().c_str());
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

    void homework_routing::getInstance(const Context* c,
                                       homework_routing*& component)
    {
        component = dynamic_cast<homework_routing*>
            (c->get_by_interface(container::Interface_description
                                 (typeid(homework_routing).name())));
    }

    /////////////////////////////////////
    //   PktIn event handling
    /////////////////////////////////////
    Disposition homework_routing::arp_handler(const Event& e) {
        // chrck for better handling ioctrl and SIOCSARP
        // it will allow to insert mac entries programmatically
        // so that you can always control what is going on in the net.
        const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
        Flow flow(pi.in_port, *(pi.get_buffer()));
        lg.info("arp received: %s(type:%x, proto:%x)", pi.get_name().c_str(), 
                flow.dl_type , flow.nw_proto);
        std::vector<boost::shared_array<char> > act;
        struct ofp_action_output *ofp_act_out;
        uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_SRC | OFPFW_DL_TYPE);      
        boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
        act.push_back(ofp_out);

        ofp_act_out=(struct ofp_action_output *)ofp_out.get();

        ofp_act_out->type = htons(OFPAT_OUTPUT);
        ofp_act_out->len = htons(sizeof(struct ofp_action_output));
        /* XXX arp responses will be sent to every outgoing port */
        ofp_act_out->port = htons((flow.dl_src != this-> bridge_mac)?OFPP_LOCAL:OFPP_FLOOD);
        ofp_act_out->max_len = htons(2000);

        this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                      pi.buffer_id, OFPFC_ADD, OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY, act);
        return STOP;
    }

    Disposition homework_routing::mac_pkt_handler(const Event& e) {
        //printf("ethernet packet handled\n");
        std::vector<boost::shared_array<char> > act;
        struct ofp_action_output *ofp_act_out; // , *ofp_act_out2;
        const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
        Flow flow(pi.in_port, *(pi.get_buffer()));
        //printf("pkt_in packet: %s\n", flow.to_string().c_str()); 

        if(flow.dl_type == ethernet::ARP) {
            lg.info("this is arp");
            this->arp_handler(e);
            return STOP;
        } else if (flow.dl_type == ethernet::PAE) {
            lg.info("this is eapol");
            this->pae_handler(e);
            return STOP;
        } else if(flow.dl_type ==  ethernet::IP) {
            //add an exception in the case of dhcp. 
            if( (flow.nw_proto == ip_::proto::UDP) && 
                (flow.tp_src == htons(68)) && 
                (flow.tp_dst ==  htons(67))) {
                return CONTINUE;
            } else if( (flow.nw_proto == ip_::proto::IGMP) && 
                       (flow.nw_dst == inet_addr("224.0.0.22"))) {
                this->igmp_handler(e);
                return STOP;
            } else {
                this->packet_in_handler(e);
            }
            return STOP;
        }

        //check if mac address is allowed to send traffic or is the br0
        if(!this->check_access(flow.dl_src) && (flow.dl_src != this->bridge_mac)) {
            lg.info("Block non-IP traffic from %s", 
                    flow.to_string().c_str()); 
            return STOP;
        }

        //check if dst mac exists and allowed to received data and send it
        else if(this->check_access(flow.dl_dst)) {
            boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
            act.push_back(ofp_out);
            ofp_act_out=(struct ofp_action_output *)ofp_out.get();
            ofp_act_out->type = htons(OFPAT_OUTPUT);
            ofp_act_out->len = htons(sizeof(struct ofp_action_output));
            ofp_act_out->port = htons(OFPP_FLOOD);
            ofp_act_out->max_len = htons(2000);

            if((0 < flow.in_port) && (flow.in_port < OFPP_MAX)) 
            {   /*  physical IN_PORT => FLOOD will *not* cover IN_PORT */
                ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
                ofp_act_out = (struct ofp_action_output *)ofp_out.get();
                memcpy(ofp_act_out, act[0].get(), sizeof(struct ofp_action_output));
                act.push_back(ofp_out);
                ofp_act_out->port = htons(OFPP_IN_PORT);
            }
#if 0
            /*
             * Need two rules here. One for IN_PORT; one for FLOOD
             * ofp_act_out->port = htons(((flow.in_port == 1)?OFPP_IN_PORT:1));
             */ 
            boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
            act.push_back(ofp_out);
            ofp_act_out = (struct ofp_action_output *)ofp_out.get();
            ofp_act_out->type = htons(OFPAT_OUTPUT);
            ofp_act_out->len = htons(sizeof(struct ofp_action_output));
            ofp_act_out->port = OFPP_FLOOD; /* htons(((flow.in_port == 1)?OFPP_IN_PORT:1)); */
            ofp_act_out->max_len = htons(2000);

            if((0 < flow.in_port) && (flow.in_port  0) /* IN_PORT != controller => FLOOD will *not* cover IN_PORT */
                {
                    boost::shared_array<char> ofp_out2(new char[sizeof(struct ofp_action_output)]);
                    act.push_back(ofp_out2);
                    ofp_act_out2 = (struct ofp_action_output*)ofp_out2.get();
                    ofp_act_out2->type = htons(OFPAT_OUTPUT);
                    ofp_act_out2->len = htons(sizeof(struct ofp_action_output));
                    ofp_act_out2->port = OFPP_IN_PORT;
                    ofp_act_out2->max_len = htons(2000);
                }

#endif

                uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_VLAN | OFPFW_DL_SRC | 
                                       OFPFW_DL_DST | OFPFW_DL_TYPE);
                this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                              pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);

                } else if(flow.dl_dst == this->bridge_mac) {
                    boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
                    act.push_back(ofp_out);
                    ofp_act_out=(struct ofp_action_output *)ofp_out.get();
                    ofp_act_out->type = htons(OFPAT_OUTPUT);
                    ofp_act_out->len = htons(sizeof(struct ofp_action_output));
                    ofp_act_out->port = htons(OFPP_LOCAL); 
                    ofp_act_out->max_len = htons(2000);
                    uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_VLAN | OFPFW_DL_SRC | 
                                           OFPFW_DL_DST | OFPFW_DL_TYPE);
                    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                                  pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);
                } 

            if(flow.dl_dst == ethernetaddr(ethbroadcast)) {
                boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
                act.push_back(ofp_out);
                ofp_act_out=(struct ofp_action_output *)ofp_out.get();
                ofp_act_out->type = htons(OFPAT_OUTPUT);
                ofp_act_out->len = htons(sizeof(struct ofp_action_output));
                ofp_act_out->port = htons(OFPP_IN_PORT);
                ofp_act_out->max_len = htons(2000);

                ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
                ofp_act_out=(struct ofp_action_output *)ofp_out.get();
                memcpy(ofp_act_out, act[0].get(), sizeof(struct ofp_action_output));
                act.push_back(ofp_out);
                ofp_act_out->port = htons(OFPP_ALL); 

                uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_SRC | OFPFW_DL_DST);
                this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                              pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);
            } else {
                lg.info("blocked mac pkt %s->%s", flow.dl_src.string().c_str(),
                        flow.dl_dst.string().c_str());
            }
            return STOP;
        }

        bool 
            homework_routing::check_access(const ethernetaddr& ether) {
            return (this->mac_permit.find(ether) != this->mac_permit.end());
            //return this->p_dhcp_proxy->is_ether_addr_routable(ether);
        }

        Disposition 
            homework_routing::igmp_handler(const Event& e) {
            const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
            Flow flow(pi.in_port, *(pi.get_buffer()));
            int i;
            struct nw_hdr hdr;
            uint8_t *data = pi.get_buffer()->data();
            int32_t data_len = pi.get_buffer()->size();
            struct igmpv3_report *report = ( struct igmpv3_report *)hdr.igmp;
            ipaddr src_addr = ipaddr(ntohl(flow.nw_src));

            printf("Igmp report %s\n", flow.dl_src.string().c_str());
            if(!extract_headers(data, data_len, &hdr)) {
                printf("Failed to parse igmp packet\n");
                return STOP;
            }

            if(hdr.igmp->type != IGMPV3_HOST_MEMBERSHIP_REPORT) {
                printf("This is not an igmp report. skipping\n");
                return STOP;
            }

            //at some point I need to time out all these values....
            report = ( struct igmpv3_report *)hdr.igmp;
            for(i = 0; i < ntohs(report->ngrec); i++) {

                ipaddr addr = ipaddr(ntohl(report->grec[i].grec_mca));

                if( (report->grec[i].grec_type == IGMPV3_CHANGE_TO_EXCLUDE) ||
                    (report->grec[i].grec_type == IGMPV3_MODE_IS_INCLUDE)) {
                    printf("joining multicast ip addr %s \n", addr.string().c_str());
                    if(this->multicast_ip.find(addr) == this->multicast_ip.end()) 
                        this->multicast_ip[addr] = std::set<ipaddr>();
                    this->multicast_ip[addr].insert(ipaddr(ntohl(flow.nw_src)));
                } else if( (report->grec[i].grec_type == IGMPV3_CHANGE_TO_INCLUDE) ||
                           (report->grec[i].grec_type == IGMPV3_MODE_IS_EXCLUDE)) {
                    printf("removing multicast ip addr %s \n", addr.string().c_str());
                    if(this->multicast_ip.find(addr) != this->multicast_ip.end()) {
                        this->multicast_ip[addr].erase(src_addr);
                        if( this->multicast_ip[addr].size() == 0)
                            this->multicast_ip.erase(addr);
                    }
                }   
            }
            return STOP;
        }

        Disposition homework_routing::pae_handler(const Event& e) {
            // chrck for better handling ioctrl and SIOCSARP
            // it will allow to insert mac entries programmatically
            // so that you can always control what is going on in the net.
            const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
            Flow flow(pi.in_port, *(pi.get_buffer()));
            lg.info("pae received: %s(type:%x, proto:%x)", pi.get_name().c_str(), 
                    flow.dl_type , flow.nw_proto);

            //this should check the mac vector
            if(this->mac_blacklist.find(flow.dl_src) != this->mac_blacklist.end() ) {
                lg.info("Skipping pae packet from blacklisted mac %s", 
                        flow.dl_src.string().c_str());
                return STOP;
            }

            std::vector<boost::shared_array<char> > act;
            struct ofp_action_output *ofp_act_out;
            uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_SRC | OFPFW_DL_TYPE);      
            boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
            act.push_back(ofp_out);

            ofp_act_out=(struct ofp_action_output *)ofp_out.get();

            ofp_act_out->type = htons(OFPAT_OUTPUT);
            ofp_act_out->len = htons(sizeof(struct ofp_action_output));
            ofp_act_out->port = htons(OFPP_LOCAL); 
            ofp_act_out->max_len = htons(2000);

            this->send_flow_modification (flow, wildcard, pi.datapath_id, pi.buffer_id, 
                                          OFPFC_ADD,OFP_FLOW_PERMANENT, OFP_DEFAULT_PRIORITY, act);

            return STOP;
        }

        Disposition 
            homework_routing::packet_in_handler(const Event& e) {
            const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
            Flow flow(pi.in_port, *(pi.get_buffer()));
            ethernetaddr dl_dst;
            // dhcp_mapping *src_state = NULL; //, *dst_state = NULL;
            bool is_src_router = (flow.in_port == OFPP_LOCAL);
            //bool is_dst_router = (flow.dl_dst == this->bridge_mac);
            bool is_dst_local = 0;
            bool is_src_local = 0;
            int dst_port = 0;
            std::vector<boost::shared_array<char> > act;
            struct ofp_action_output *ofp_act_out;
            struct ofp_action_dl_addr *ofp_act_dl_addr;
            uint32_t wildcard = 0;   

            lg.info("Pkt in %s", flow.to_string().c_str());

            //check if src ip is routable and the src mac address is permitted.
            if(this->non_routable.matches(ipaddr(ntohl(flow.nw_src))) ) {
                lg.info("src ip %s is not routable. Better wait to get proper ip.\n", 
                        ipaddr(ntohl(flow.nw_src)).string().c_str());
                return STOP;
            }

            //check if src ip is routable and the src mac address is permitted.
            if( (flow.dl_src != this->bridge_mac) && 
                (!this->check_access(flow.dl_src)) ) {
                lg.info("MAC address %s is not permitted to send data", flow.dl_src.string().c_str());
                return STOP;
            } 

            //check if dst ip is routable and we have a mac address for it.
            if(this->non_routable.matches(ipaddr(ntohl(flow.nw_dst))) ) {
                lg.info("dst ip %s is not routable.", ipaddr(ntohl(flow.nw_dst)).string().c_str());
                return STOP;
            }

            // find state for source - in case the address comes 
            // from the server ignore state rquirement. 
            is_src_local = (this->routable.matches(ipaddr(ntohl(flow.nw_src)))
                            || this->init_subnet.matches(ipaddr(ntohl(flow.nw_src))));

            if((is_src_local) && (ntohl(flow.nw_src)&0x3) == 1) {
                if ( (!this->p_dhcp->is_valid_mapping(ipaddr(ntohl(flow.nw_src)), flow.dl_src)) &&
                     (flow.dl_src != this->bridge_mac)) {
                    lg.info("received packet from unrecorded mac. "
                            "i discarding (dl_src:%s bridge_mac:%s)\n", 
                            flow.dl_src.string().c_str(), 
                            this->bridge_mac.string().c_str());
                    return STOP;
                }
            }


            //check if destination ip is multicast and flood network in this case
            if(this->multicast.matches(ipaddr(ntohl(flow.nw_dst))) ) {
                if(this-> multicast_ip.find(flow.nw_dst) != this-> multicast_ip.end()) {
                    boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
                    act.push_back(ofp_out);
                    ofp_act_out = (struct ofp_action_output *)ofp_out.get();
                    ofp_act_out->type = htons(OFPAT_OUTPUT);
                    ofp_act_out->len = htons(sizeof(struct ofp_action_output));
                    ofp_act_out->port = htons(OFPP_IN_PORT);
                    ofp_act_out->max_len = htons(2000);

                    ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
                    ofp_act_out = (struct ofp_action_output *)ofp_out.get();
                    memcpy(ofp_act_out, act[0].get(), sizeof(struct ofp_action_output));
                    act.push_back(ofp_out);
                    ofp_act_out->port = htons(OFPP_FLOOD); 

                    uint32_t wildcard = 0;
                    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                                  pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);
                    lg.info("Flood multicast packets");
                }
                return STOP;
            }

            //check if destination ip is broadcast and flood network in this case
            //with a longer broadcast ip

            /* in fact, insert a rule which rewrites the dst_ip to be the 10.2.255.255 broadcast
             * since 10.2.x.y where y = 0b...11 is too specific a subnet broadcast.  send the
             * rewritten packet back to the controller (port=0).
             */
            if(this->routable.matches(ipaddr(ntohl(flow.nw_dst))) && 
               ((ntohl(flow.nw_dst) & 0x3) == 0x3)) {
                boost::shared_array<char> ofp_out(new char[sizeof(struct  ofp_action_nw_addr)]);
                act.push_back(ofp_out);
                ofp_action_nw_addr *nw_addr=(struct  ofp_action_nw_addr *)ofp_out.get();
                nw_addr->type = htons(OFPAT_SET_NW_DST);
                nw_addr->len = htons(sizeof(struct ofp_action_nw_addr ));
                nw_addr->nw_addr = inet_addr("10.2.255.255"); 
                //      ofp_act_out->max_len = htons(2000);
                
                ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
                ofp_act_out=(struct ofp_action_output *)ofp_out.get();
                memcpy(ofp_act_out, act[0].get(), sizeof(struct ofp_action_output));
                act.push_back(ofp_out);
                ofp_act_out->port = (flow.in_port == 0)?htons(OFPP_IN_PORT):0; 
                uint32_t wildcard = 0;
            
                this->send_flow_modification(flow, wildcard, pi.datapath_id,
                                             pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);
                lg.info("Broadcast packet detected");
                return STOP;
            }

#if 0
            /* rather complex, rewrite below */
            //checkin proper output port by checkin the dst mac and ip
            if(this->routable.matches(ipaddr(ntohl(flow.nw_dst))) ) {
                //destination is local
                //required assumption for  packet destined to the bridged intf.
                if((ntohl(flow.nw_dst) & 0x1) == 0x1) {
                    dst_port = 1;
                    //required properties for a packet to be destined to one of the internal hosts.
                    //TODO: what if the destination is not allowed to talk?
                } else {
                    //output to port 1
                    lg.info("packet destined to port 1");
                    dst_port = 0;
                }
            } else {
                dst_port = 0;
            }
#endif

            if((this->routable.matches(ipaddr(ntohl(flow.nw_dst))))
               && ((ntohl(flow.nw_dst) & 0x01) == 0x01))
            { /* dst_ip is routable AND is either a host OR a BROADCAST */
                dst_port = 1;
            }
            else
            {
                dst_port = 0;
            }

            int last_act = 0;
            is_dst_local = (this->routable.matches(ipaddr(ntohl(flow.nw_dst)))
                            || this->init_subnet.matches(ipaddr(ntohl(flow.nw_dst))));
            if(is_dst_local && is_src_local && (dst_port != 0) && (!is_src_router)) 
            {
                /* The following conditions held, pre-wired-interface:
                 * - local destination -> dst_ip is routable OR dst_ip is broadcast
                 * - local source -> src_ip is routable OR src_ip is broadcast (?)
                 * - dst_ip is routable AND dst_ip is a host on a homework subnet, thus dst_port = 1 (wlan0)
                 * - source is NOT the router
                 */
                ethernetaddr dst_mac = this->p_dhcp->get_mac(ipaddr(ntohl(flow.nw_dst)));

                boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_dl_addr)]);
                act.push_back(ofp_out);
                ofp_act_dl_addr = (ofp_action_dl_addr *)ofp_out.get();
                ofp_act_dl_addr->type = htons(OFPAT_SET_DL_SRC);
                ofp_act_dl_addr->len = htons(sizeof(ofp_action_dl_addr));
                memcpy(ofp_act_dl_addr->dl_addr, (const uint8_t *)this->bridge_mac, sizeof ofp_act_dl_addr->dl_addr);

                ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_dl_addr)]);
                act.push_back(ofp_out);
                ofp_act_dl_addr = (ofp_action_dl_addr *)ofp_out.get();
                ofp_act_dl_addr->type = htons(OFPAT_SET_DL_DST);
                ofp_act_dl_addr->len = htons(sizeof(ofp_action_dl_addr));
                memcpy(ofp_act_dl_addr->dl_addr, (const uint8_t *)dst_mac, sizeof ofp_act_dl_addr->dl_addr);

                last_act = 2;
                /* 
                   ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_dl_addr)]);
                   act.push_back(ofp_out);
                   ofp_act_out = (ofp_action_output *)ofp_out.get();
                   ofp_act_out->type = htons(OFPAT_OUTPUT);
                   ofp_act_out->len = htons(sizeof(ofp_action_output));
                   ofp_act_out->max_len = htons(2000);
                
                   ofp_act_out->port = (dst_port==flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port);
                */
            } else {
                /* ANY of these conditions holds:
                 * - not local destination -> would've been dropped
                 * - not local source -> would've been dropped
                 * - dst_ip is not routable (would've been dropped) OR is not a host on a homework subnet
                 *   ie., dst_port = 0 which will mean controller
                 * - source is the router -> packet could've come from ISP uplink via NAT
                 */
                /* if source is router, dst_port = 0|1 cannot be flow.in_port so will send to 
                 * dst_port -- which WILL BE 1 = wlan0 if dst_ip (after NAT!) is routable
                 */
                /*
                  boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
                  act.push_back(ofp_out);
                  ofp_act_out = (ofp_action_output *)ofp_out.get();
                  ofp_act_out->type = htons(OFPAT_OUTPUT);
                  ofp_act_out->len = htons(sizeof(ofp_action_output));
                  ofp_act_out->max_len = htons(2000);
                  ofp_act_out->port = (dst_port==flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port);
                */
            }

            /* XXX if we've got this far, simply forward packet out of IN_PORT and FLOOD */

            boost::shared_array<char> ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
            act.push_back(ofp_out);
            ofp_act_out = (ofp_action_output *)ofp_out.get();
            ofp_act_out->type = htons(OFPAT_OUTPUT);
            ofp_act_out->len = htons(sizeof(ofp_action_output));
            ofp_act_out->max_len = htons(2000);
            ofp_act_out->port = htons(OFPP_FLOOD);
            
            if((0 < flow.in_port) && (flow.in_port < OFPP_MAX))
            {
                ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_output)]);
                ofp_act_out = (struct ofp_action_output *)ofp_out.get();
                memcpy(ofp_act_out, act[last_act].get(), sizeof(struct ofp_action_output));
                act.push_back(ofp_out);
                ofp_act_out->port = htons(OFPP_IN_PORT); 
            }

            this->send_flow_modification (flow, wildcard, pi.datapath_id,
                                          pi.buffer_id, OFPFC_ADD, 30, OFP_DEFAULT_PRIORITY, act);
            return STOP;
        }

        //////////////////////////////////
        //  Homework interaction 
        /////////////////////////////////
        std::vector<std::string> 
            homework_routing::get_dhcp_mapping() { 
            return this->p_dhcp->get_dhcp_mapping();
        };

        std::vector<std::string> 
            homework_routing::get_blacklist_status() {
            std::vector<std::string> v;
            std::set<ethernetaddr>::iterator it = this->mac_blacklist.begin();
            for(;it!=this->mac_blacklist.end();it++) {
                printf("pushing: %s\n", it->string().c_str());
                v.push_back(it->string());
            }
            return v;
        }

        void 
            homework_routing::whitelist_mac(const ethernetaddr& ether) {
            //add element in the vector 
            if(this->mac_blacklist.find(ether) != this->mac_blacklist.end()) 
                this->mac_blacklist.erase(this->mac_blacklist.find(ether) );
            if(this->mac_permit.find(ether) != this->mac_permit.end()) 
                this->mac_permit.erase(ether);

            this->revoke_mac_access(ether);
        }

        void 
            homework_routing::permit_mac(const ethernetaddr& ether) {
            //add element in the vector
            printf("permitting mac %s\n", ether.string().c_str());
            this->mac_permit.insert(ether);
        }

        void 
            homework_routing::blacklist_mac(const ethernetaddr& ether) {
            //add element in the vector 
            this->mac_blacklist.insert(ether); 
            std::vector<datapathid *>::iterator it;
            printf("blaclisting : %s\n", ether.string().c_str());

            //send command to delete flow from cache        
            ofp_flow_mod* ofm;
            size_t size = sizeof(*ofm);
            boost::shared_array<char> raw_of(new char[size]);
            ofm = (ofp_flow_mod*) raw_of.get();
            bzero(ofm, size);
            ofm->header.version = OFP_VERSION;
            ofm->header.type = OFPT_FLOW_MOD;
            ofm->header.length = htons(size);
            ofm->match.wildcards =htonl(~( OFPFW_DL_SRC | OFPFW_DL_TYPE));
            ofm->match.dl_type =  ethernet::PAE; 
            memcpy(ofm->match.dl_src, ether.octet, sizeof ether);
            ofm->command = htons(OFPFC_DELETE);
            ofm->buffer_id = htonl(-1);
            ofm-> out_port = OFPP_NONE;
            for(it = this->registered_datapath.begin(); it < this->registered_datapath.end(); it++) {
                send_openflow_command(**it, &ofm->header, false);
            }
        }

        void
            homework_routing::revoke_mac_access(const ethernetaddr& ether) {
            ofp_flow_mod* ofm;
            size_t size = sizeof(ofp_flow_mod);
            vector<datapathid *>::iterator it;
            boost::shared_array<char> raw_of(new char[size]);

            ofm = (ofp_flow_mod*) raw_of.get();
            bzero(ofm, size);
            ofm->header.version = OFP_VERSION;
            ofm->header.type = OFPT_FLOW_MOD;
            ofm->header.length = htons(size);
            ofm->match.wildcards =htonl(~OFPFW_DL_SRC);
            memcpy(ofm->match.dl_src, (const uint8_t *)ether, OFP_ETH_ALEN);
            ofm->out_port = OFPP_NONE;
            ofm->command = htons(OFPFC_DELETE);
            for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
                send_openflow_command(**it, &ofm->header, false);
            }

            raw_of= boost::shared_array<char> (new char[size]);
            ofm = (ofp_flow_mod*) raw_of.get();
            bzero(ofm, size);
            ofm->header.version = OFP_VERSION;
            ofm->header.type = OFPT_FLOW_MOD;
            ofm->header.length = htons(size);
            ofm->match.wildcards =htonl(~OFPFW_DL_DST);
            memcpy(ofm->match.dl_dst, (const uint8_t *)ether, OFP_ETH_ALEN);
            ofm->out_port = OFPP_NONE;
            ofm->command = htons(OFPFC_DELETE);
            for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
                send_openflow_command(**it, &ofm->header, false);
            }
        }

        /////////////////////////////////////
        //   Packet generation methods
        /////////////////////////////////////
        bool 
            homework_routing::send_flow_modification (Flow flow, uint32_t wildcard,  datapathid datapath_id,
                                                      uint32_t buffer_id, uint16_t command, uint16_t timeout, uint16_t prio,
                                                      std::vector<boost::shared_array<char> > act) {

            std::vector< boost::shared_array<char> >::iterator iter;
            ofp_flow_mod* ofm;
            size_t size = sizeof(*ofm);
            struct ofp_action_header *ofp_hdr;

            for(iter = act.begin() ; iter != act.end(); iter++) {
                ofp_hdr = (struct ofp_action_header *)iter->get();
                size += ntohs(ofp_hdr->len);
            }    
            boost::shared_array<char> raw_of(new char[size]);
            ofm = (ofp_flow_mod*) raw_of.get();
            ofm->header.version = OFP_VERSION;
            ofm->header.type = OFPT_FLOW_MOD;
            ofm->header.length = htons(size);
            ofm->match.wildcards = htonl(wildcard);
            ofm->match.in_port = htons(flow.in_port);
            ofm->match.dl_vlan = flow.dl_vlan;
            ofm->match.dl_vlan_pcp = flow.dl_vlan_pcp;
            memcpy(ofm->match.dl_src, flow.dl_src.octet, sizeof ofm->match.dl_src);
            memcpy(ofm->match.dl_dst, flow.dl_dst.octet, sizeof ofm->match.dl_dst);
            ofm->match.dl_type = flow.dl_type;
            ofm->match.nw_src = flow.nw_src;
            ofm->match.nw_dst = flow.nw_dst;
            ofm->match.nw_proto = flow.nw_proto;
            ofm->match.nw_tos = flow.nw_tos;
            ofm->match.tp_src = flow.tp_src;
            ofm->match.tp_dst = flow.tp_dst;
            ofm->cookie = htonl(0);
            ofm->command = htons(command);
            ofm->buffer_id = htonl(buffer_id);
            ofm->idle_timeout = htons(timeout);
            ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
            ofm->priority = htons(prio); //OFP_DEFAULT_PRIORITY);
            ofm->flags = htons( OFPFF_SEND_FLOW_REM); // | OFPFF_CHECK_OVERLAP);

            char *data = (char *)ofm->actions;
            int pos = 0;
            for(iter = act.begin() ; iter != act.end(); iter++) {
                ofp_hdr = (struct ofp_action_header *)iter->get();
                memcpy(data+pos, iter->get(), ntohs(ofp_hdr->len));
                pos += ntohs(ofp_hdr->len);
            }
            send_openflow_command(datapath_id, &ofm->header, false);
            return true;
        }

        bool homework_routing::extract_headers(uint8_t *data, uint32_t data_len, 
                                               struct nw_hdr *hdr) {
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

        REGISTER_COMPONENT(Simple_component_factory<homework_routing>,
                           homework_routing);
    } // vigil namespace
