#include "dhcp.hh"
#include "dhcp_proxy.hh"

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
#include "dhcp_mapping.hh"

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

const char *dhcp_msg_type_name[] = {NULL, "DHCPDiscover", "DHCPOffer", 
                    "DHCPRequest", "DHCPDecline", "DHCPAck", 
                    "DHCPNak", "DHCPRelease", "DHCPInform"};
namespace vigil
{
  static Vlog_module lg("dhcp");

  /////////////////////////////////////
  //   module configuration 
  /////////////////////////////////////
  void dhcp::configure(const Configuration* c) {
    struct nl_cache *cache;
    unsigned char addr[ETH_ALEN];
    struct ifreq ifr;
    int s;
    this->rpc = NULL;

    lg.dbg(" Configure called ");
    
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

  }

void dhcp::insert_hwdb(const char *action, const char *ip, 
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
	bytes += sprintf(q + bytes, "\"%s\", ", mac);
	/* mac address */
	bytes += sprintf(q + bytes, "\"%s\", ", ip);
	/* ip address */
	bytes += sprintf(q + bytes, "\"%s\", ", hostname);
	/* hostname (optional) */
	bytes += sprintf(q + bytes, "\"%s\")\n",action);
	
	fprintf(stderr, "%s", q);
	if (! rpc_call(rpc, q, bytes, r, sizeof(r), &rlen)) {
		fprintf(stderr, "rpc_call() failed\n");
		return;
	}
	r[rlen] = '\0';
	if (rtab_status(r, stsmsg))
		fprintf(stderr, "RPC error: %s\n", stsmsg);
  }


  void dhcp::install() {
	
	/*HWDB*/
	const char *host;
	unsigned short port;
	const char *service;
	host = HWDB_SERVER_ADDR;
	port = HWDB_SERVER_PORT;
	service = "HWDB";

    lg.dbg(" Install called ");
    //register_handler<Packet_in_event>(boost::bind(&dhcp::packet_in_handler, this, _1));
    register_handler<Packet_in_event>(boost::bind(&dhcp::mac_pkt_handler, this, _1));

    register_handler<Datapath_join_event>(boost::bind(&dhcp::datapath_join_handler, this, _1));
    register_handler<Datapath_leave_event>(boost::bind(&dhcp::datapath_leave_handler, this, _1));
    //timeval tv = {1,0};
    //post(boost::bind(&dhcp::refresh_default_flows, this), tv);
	
	/*HWDB*/
	rpc = NULL;
	if (!rpc_init(0)) {
		fprintf(stderr, "Failure to initialize rpc system\n");
		return;
	}
	if (!(rpc = rpc_connect(const_cast<char *>(host), port, const_cast<char *>(service), 1l))) {
		fprintf(stderr, "Failure to connect to HWDB at %s:%05u\n", host, port);
		return;
	}
    }

  void 
  dhcp::getInstance(const Context* c,
             dhcp*& component) {
    component = dynamic_cast<dhcp*>
      (c->get_by_interface(container::Interface_description
               (typeid(dhcp).name())));
  }

  //////////////////////////////////////////////////
  //     Timer event handling
  //////////////////////////////////////////////////
  void 
  dhcp::refresh_default_flows() {
    std::vector<datapathid *>::iterator it;
    ofp_flow_mod* ofm;
    size_t size = sizeof *ofm + sizeof(ofp_action_output);
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    // for(it = this->registered_datapath.begin(); it < this->registered_datapath.end(); it++) {
    //   generate_openflow_dhcp_flow(ofm, size);
    //   send_openflow_command(**it, &ofm->header, true);
    // }
    timeval tv = {FLOW_TIMEOUT_DURATION,0};
    post(boost::bind(&dhcp::refresh_default_flows, this), tv);
  }
  
  /////////////////////////////////////
  //   Datapath event handling
  /////////////////////////////////////
  Disposition dhcp::datapath_join_handler(const Event& e) {
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
    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                  -1, OFPFC_ADD, OFP_FLOW_PERMANENT, act);

    //force to forward igmp traffic to controller. 
    flow.dl_type = ethernet::IP;
    flow.nw_proto = ip_::proto::IGMP;
    wildcard = ~(OFPFW_DL_TYPE | OFPFW_NW_PROTO);   
    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                  -1, OFPFC_ADD,OFP_FLOW_PERMANENT, act);
    return CONTINUE;
  }

  Disposition dhcp::datapath_leave_handler(const Event& e) {
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

  /////////////////////////////////////
  //   PktIn event handling
  /////////////////////////////////////
  Disposition dhcp::arp_handler(const Event& e) {
    // chrck for better handling ioctrl and SIOCSARP
    // it will allow to insert mac entries programmatically
    // so that you can always control what is going on in the net.
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    printf("arp received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
           flow.dl_type , flow.nw_proto);
    std::vector<boost::shared_array<char> > act;
    struct ofp_action_output *ofp_act_out;
    uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_SRC | OFPFW_DL_TYPE);      
    boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
    act.push_back(ofp_out);

    ofp_act_out=(struct ofp_action_output *)ofp_out.get();

    ofp_act_out->type = htons(OFPAT_OUTPUT);
    ofp_act_out->len = htons(sizeof(struct ofp_action_output));
    ofp_act_out->port = htons((flow.dl_src != this-> bridge_mac)?OFPP_LOCAL:1); 
    ofp_act_out->max_len = htons(2000);

    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                  pi.buffer_id, OFPFC_ADD, OFP_FLOW_PERMANENT, act);
    return STOP;
  }

  Disposition dhcp::mac_pkt_handler(const Event& e) {
    //printf("ethernet packet handled\n");
    std::vector<boost::shared_array<char> > act;
    struct ofp_action_output *ofp_act_out;
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    //printf("pkt_in packet: %s\n", flow.to_string().c_str()); 

    if(flow.dl_type == ethernet::ARP) {
      printf("this is arp\n");
      this->arp_handler(e);
      return STOP;
    } else if (flow.dl_type == ethernet::PAE) {
      printf("this is eapol\n");
      this->pae_handler(e);
      return STOP;
    } else if(flow.dl_type ==  ethernet::IP) {
      //add an exception in the case of dhcp. 
      if( (flow.nw_proto == ip_::proto::UDP) && 
          (flow.tp_src == htons(68)) && 
          (flow.tp_dst ==  htons(67))) {
        this->dhcp_handler(e);
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
      printf("MAC layer transmission blocked because mac is not allowed:(%s)\n", 
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
      ofp_act_out->port = htons(((flow.in_port == 1)?OFPP_IN_PORT:1)); 
      ofp_act_out->max_len = htons(2000);
      uint32_t wildcard = ~( OFPFW_IN_PORT | OFPFW_DL_VLAN | OFPFW_DL_SRC | 
                 OFPFW_DL_DST | OFPFW_DL_TYPE);
      this->send_flow_modification (flow, wildcard, pi.datapath_id,
                    pi.buffer_id, OFPFC_ADD, 30, act);
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
                    pi.buffer_id, OFPFC_ADD, 30, act);
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
                    pi.buffer_id, OFPFC_ADD, 30, act);
    } else {
      printf("mac pkt %s->%s can't be delivered\n", 
         flow.dl_src.string().c_str(), flow.dl_dst.string().c_str());
    }
    return STOP;
  }

  Disposition 
  dhcp::igmp_handler(const Event& e) {
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

  Disposition dhcp::pae_handler(const Event& e) {
    // chrck for better handling ioctrl and SIOCSARP
    // it will allow to insert mac entries programmatically
    // so that you can always control what is going on in the net.
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    printf("pae received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
           flow.dl_type , flow.nw_proto);
    
    //this should check the mac vector
    if(this->mac_blacklist.find(flow.dl_src) != this->mac_blacklist.end() ) {
      printf("Skipping pae packet from blacklisted mac %s\n", 
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
                  OFPFC_ADD,OFP_FLOW_PERMANENT, act);
    
    return STOP;
  }
  
  Disposition 
  dhcp::packet_in_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    ethernetaddr dl_dst;
    dhcp_mapping *src_state = NULL; //, *dst_state = NULL;
    bool is_src_router = (flow.in_port == OFPP_LOCAL);
    //bool is_dst_router = (flow.dl_dst == this->bridge_mac);
    bool is_dst_local = 0;
    bool is_src_local = 0;
    int dst_port = 0;
    std::vector<boost::shared_array<char> > act;
    struct ofp_action_output *ofp_act_out;
    struct ofp_action_dl_addr *ofp_act_dl_addr;
    uint32_t wildcard = 0;   

    printf("Pkt in received: %s(type:%x, proto:%x) %s->%s,%s->%s\n", 
       pi.get_name().c_str(), 
       flow.dl_type, flow.nw_proto, flow.dl_src.string().c_str(), 
       flow.dl_dst.string().c_str(), ipaddr(ntohl(flow.nw_src)).string().c_str(), 
       ipaddr(ntohl(flow.nw_dst)).string().c_str());

    //check if src ip is routable and the src mac address is permitted.
    if(ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, 
            ipaddr(ntohl(flow.nw_src))) ) {
      printf("src ip %s is not routable. Better wait to get proper ip.\n", 
         ipaddr(ntohl(flow.nw_src)).string().c_str());
      return STOP;
    }

    //check if src ip is routable and the src mac address is permitted.
    if( (flow.dl_src != this->bridge_mac) && 
       (!this->p_dhcp_proxy->is_ether_addr_routable(flow.dl_src)) ) {
      printf("MAC address %s is not permitted to send data\n", flow.dl_src.string().c_str());
      return STOP;
    } 
    
    //check if dst ip is routable and we have a mac address for it.
    if(ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, 
           ipaddr(ntohl(flow.nw_dst))) ) {
      printf("dst ip %s is not routable.\n", ipaddr(ntohl(flow.nw_dst)).string().c_str());
      return STOP;
    }

    // find state for source - in case the address comes 
    // from the server ignore state rquirement. 
    is_src_local = ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, ipaddr(ntohl(flow.nw_src))) || ip_matching(ipaddr(INIT_SUBNET), INIT_NETMASK, ipaddr(ntohl(flow.nw_src)));

    if (  (is_src_local) && (ntohl(flow.nw_src)&0x3) == 1) {
      if((this->mac_mapping.find(flow.dl_src) == this->mac_mapping.end())  || 
     ((src_state = this->mac_mapping[flow.dl_src]) == NULL) ){
    printf("No state found for source mac %s\n", ethernetaddr(flow.dl_src).string().c_str());
    return STOP;
      }  
      if( src_state->ip != flow.nw_src ){
    printf("Source hosts uses unassigned ip address\n");
    return STOP;
      }
    } else if(flow.dl_src != this->bridge_mac) {
      printf("received packet from unrecorded mac. discarding (dl_src:%s bridge_mac:%s)\n", 
         flow.dl_src.string().c_str(), this->bridge_mac.string().c_str());
      return STOP;
    }
    
    
    //check if destination ip is multicast and flood network in this case
    if(ip_matching(ipaddr(MULTICAST_SUBNET), MULTICAST_NETMASK, 
           ipaddr(ntohl(flow.nw_dst))) ) {
      if(this-> multicast_ip.find(flow.nw_dst) != this-> multicast_ip.end()) {
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
    uint32_t wildcard = 0;
    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                      pi.buffer_id, OFPFC_ADD, 30, act);
    printf("Flood multicast packets\n");
      }
      return STOP;
    }
    
    //check if destination ip is broadcasr and flood network in this case
    //with a longer broadcast ip
    if(ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, 
           ipaddr(ntohl(flow.nw_dst))) && ((ntohl(flow.nw_dst) & 0x3) == 0x3)) {
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
                    pi.buffer_id, OFPFC_ADD, 30, act);
      printf("Broadcast packet detected\n");
      return STOP;
    }

    //checkin proper output port by checkin the dst mac and ip
    if(this->ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, 
            ipaddr(ntohl(flow.nw_dst))) ) {
      //destination is local
      //required assumption for  packet destined to the bridged intf. 
      if((flow.dl_dst == this->bridge_mac) && 
     (this->ip_mapping.find(ipaddr(htonl(flow.nw_dst) - 1)) != this->ip_mapping.end())) {

    dst_port = 0;
    //required properties for a packet to be destined to one of the internal hosts.
      } else if ( (this->ip_mapping.find(ipaddr(ntohl(flow.nw_dst))) != this->ip_mapping.end()) ) {
    //output to port 1
    printf("packet destined to port 1\n");
    dst_port = 1;
      } else {
    return STOP;
      }
    } else {
      dst_port = 0;
    }

    is_dst_local = ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, ipaddr(ntohl(flow.nw_dst))) || ip_matching(ipaddr(INIT_SUBNET), INIT_NETMASK, ipaddr(ntohl(flow.nw_dst)));
    if(is_dst_local && is_src_local && (dst_port != 0) && (!is_src_router)) {
      boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_dl_addr)]);
      act.push_back(ofp_out);
      ofp_act_dl_addr = (ofp_action_dl_addr *)ofp_out.get(); 
      ofp_act_dl_addr->type = htons(OFPAT_SET_DL_SRC);
      ofp_act_dl_addr->len = htons(sizeof(ofp_action_dl_addr));
      memcpy(ofp_act_dl_addr->dl_addr, (const uint8_t *)this->bridge_mac, 
         sizeof ofp_act_dl_addr->dl_addr);

      ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_dl_addr)]);
      act.push_back(ofp_out);
      ofp_act_dl_addr = (ofp_action_dl_addr *)ofp_out.get();
      ofp_act_dl_addr->type = htons(OFPAT_SET_DL_DST);
      ofp_act_dl_addr->len = htons(sizeof(ofp_action_dl_addr));
      memcpy(ofp_act_dl_addr->dl_addr, 
         (const uint8_t *)this->ip_mapping[ipaddr(ntohl(flow.nw_dst))]->mac, 
         sizeof ofp_act_dl_addr->dl_addr);

      ofp_out = boost::shared_array<char>(new char[sizeof(struct ofp_action_dl_addr)]);
      act.push_back(ofp_out);
      ofp_act_out = (ofp_action_output *)ofp_out.get();
      ofp_act_out->type = htons(OFPAT_OUTPUT);
      ofp_act_out->len = htons(sizeof(ofp_action_output));
      ofp_act_out->max_len = htons(2000);    
      ofp_act_out->port = (dst_port==flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port);
    } else {   
      boost::shared_array<char> ofp_out(new char[sizeof(struct ofp_action_output)]);
      act.push_back(ofp_out);
      ofp_act_out = (ofp_action_output *)ofp_out.get(); 
      ofp_act_out->type = htons(OFPAT_OUTPUT);
      ofp_act_out->len = htons(sizeof(ofp_action_output));
      ofp_act_out->max_len = htons(2000);    
      ofp_act_out->port = (dst_port==flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port);
    }
    this->send_flow_modification (flow, wildcard, pi.datapath_id,
                  pi.buffer_id, OFPFC_ADD, 30, act);
    return STOP;
  }
  
  Disposition dhcp::dhcp_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));

    // for some reason events are only fired for this action when nox 
    // sees udp traffic. 
    if( (ntohs(flow.tp_dst) != 67) || (ntohs(flow.tp_src) != 68)) {
      printf("This is not DHCP traffic!\n");
      this->packet_in_handler(e);
      return CONTINUE;
    }  
    
    uint8_t *data = pi.get_buffer()->data(), *reply = NULL;
    int32_t data_len = pi.get_buffer()->size();
    int pointer = 0;

    struct nw_hdr hdr;
    if(!this->extract_headers(data, data_len, &hdr)) {
      printf("malformed dhcp packet \n");
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
    bool is_routable =
      (this->ip_matching(ipaddr(ROUTABLE_SUBNET),ROUTABLE_NETMASK, ntohl((uint32_t)send_ip)) || 
       (this->ip_matching(ipaddr(INIT_SUBNET),INIT_NETMASK, ntohl((uint32_t)send_ip))));
    bool is_init =  (this->ip_matching(ipaddr(INIT_SUBNET),INIT_NETMASK, ntohl((uint32_t)send_ip)));

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
  
  //////////////////////////////////////////
  // Mapping manipulation functions
  /////////////////////////////////////////
  inline bool
  dhcp::ip_matching(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip) {
    return (((ntohl(ip)) & (0xFFFFFFFF<<netmask)) == ntohl(subnet));
  }

  inline bool
  dhcp::is_ip_broadcast(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip) {
    return  (((ntohl(ip)) & (0xFFFFFFFF<<netmask)) == ntohl(subnet)) &&
      (ntohl(ip) && (~(0xFFFFFFFF<<netmask)) == (~(0xFFFFFFFF<<netmask)));
  }
  inline bool
  dhcp::is_ip_host(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip) {
    return  (((ntohl(ip)) & (0xFFFFFFFF<<netmask)) == ntohl(subnet)) &&
      (ntohl(ip) && (~(0xFFFFFFFF<<netmask)) == 1);
  }
  inline bool
  dhcp::is_ip_router(const ipaddr& subnet, uint32_t netmask,const ipaddr& ip) {
    return  (((ntohl(ip)) & (0xFFFFFFFF<<netmask)) == ntohl(subnet)) &&
      (ntohl(ip) && (~(0xFFFFFFFF<<netmask)) == 2);
  }

  uint32_t
  dhcp::find_free_ip(const ipaddr& subnet, int netmask) {
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

  ipaddr 
  dhcp::select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type, uint32_t requested_ip) {
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

      //printf("found mapping for addr %s -> %s\n", ether.string().c_str(), 
      //state->string().c_str());
      //check if the ip is routable and if the web service agrees on that. 
      // if( (!ip_matching(ipaddr((is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET)), 
      //            ((is_routable)? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK), state->ip)) &&
      //      (state->state == DHCP_STATE_FINAL) ) {
      //    printf("ip assingment is invalid!\n");  

      //    //remove old mapping
      //    if(this->ip_mapping.find(state->ip) != this->ip_mapping.end())
      //      this->ip_mapping.erase(state->ip);
      //    if(this->mac_mapping.find(state->mac) != this->mac_mapping.end()) 
      //      this->mac_mapping.erase(state->mac);
      //    delete state;

      //    //generate new mapping
      //    ip = find_free_ip(ipaddr(is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET), 
      //              is_routable? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK);

      //    printf("lease end: %ld %ld\n",  tv.tv_sec, lease_end);
      //    ip++;
      //    state = new dhcp_mapping(ipaddr(ip), ether, lease_end, DHCP_STATE_FINAL);
      //    //printf("inserting new entry for %s - %s\n", ether.string().c_str(), 
      //    //state->string().c_str());
      //    this->mac_mapping[ether] = state;
      //    this->ip_mapping[ipaddr(ip)] = state;
      // }
      // if((requested_ip == ntohl(state->ip)) && (dhcp_msg_type == DHCPREQUEST))
      //    state->state = DHCP_STATE_FINAL;
    } else {
      //check whether you might need to delete some old mapping on the ip map.
      // ip = find_free_ip(ipaddr(is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET), 
      //            is_routable? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK);
      // ip = find_free_ip(ipaddr(is_routable? ROUTABLE_SUBNET: INIT_SUBNET), 
      //            is_routable? ROUTABLE_NETMASK: INIT_NETMASK); 
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

  //////////////////////////////////
  //  Homework interaction 
  /////////////////////////////////
  void dhcp::register_proxy(applications::dhcp_proxy *_p_dhcp_proxy) {
    this->p_dhcp_proxy = _p_dhcp_proxy;
    //printf("got proxy: %s\n", this->p_dhcp_proxy->hello_world().c_str());
  }  

  std::string
  dhcp::hello_world() {
    return string("Hello World!!!");
  }

  std::vector<std::string> 
  dhcp::get_dhcp_mapping() { 
    std::map<struct ethernetaddr, struct dhcp_mapping *>::iterator iter = 
      this->mac_mapping.begin();
    std::vector<std::string> v;
    for (; iter != this->mac_mapping.end(); iter++) {
      if(iter->second == NULL) continue;
      v.push_back(iter->second->string()); 
    }
    return v;
  };

  std::vector<std::string> 
  dhcp::get_blacklist_status() {
    std::vector<std::string> v;
    std::set<ethernetaddr>::iterator it = this->mac_blacklist.begin();
    for(;it!=this->mac_blacklist.end();it++) {
      printf("pushing: %s\n", it->string().c_str());
      v.push_back(it->string());
    }
    return v;
  }

  bool 
  dhcp::check_access(const ethernetaddr& ether) {
    return this->p_dhcp_proxy->is_ether_addr_routable(ether);
  }

  void 
  dhcp::whitelist_mac(const ethernetaddr& ether) {
    //add element in the vector 
    if(this->mac_blacklist.find(ether) != this->mac_blacklist.end()) 
      this->mac_blacklist.erase(this->mac_blacklist.find(ether) ); 
  }

  void 
  dhcp::blacklist_mac(ethernetaddr& ether) {
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
  dhcp::revoke_mac_access(const ethernetaddr& ether) {
    struct dhcp_mapping *state = NULL;
    ofp_flow_mod* ofm;
    size_t size = sizeof(ofp_flow_mod);
    vector<datapathid *>::iterator it;

    printf("deleting state of %s\n", ether.string().c_str());
    if(this->mac_mapping.find(ether) == this->mac_mapping.end()) {
      printf("No state found for %s\n", ether.string().c_str());
      return;
    }
    state = this->mac_mapping[ether];

    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    bzero(ofm, size);
    //TODO: also send fm command to remove all flows. 
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards =htonl(~OFPFW_DL_SRC);
    memcpy(ofm->match.dl_src, (const uint8_t *)ether, OFP_ETH_ALEN);
    ofm->command = htons(OFPFC_DELETE);
    for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
      send_openflow_command(**it, &ofm->header, false);
    }
    raw_of= boost::shared_array<char> (new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    bzero(ofm, size);
    //TODO: also send fm command to remove all flows. 
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards =htonl(~OFPFW_DL_DST);
    memcpy(ofm->match.dl_dst, (const uint8_t *)ether, OFP_ETH_ALEN);
    ofm->command = htons(OFPFC_DELETE);
    for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
      send_openflow_command(**it, &ofm->header, false);
    }
    ofp_header *ofh = NULL;
    size = sizeof(ofp_header);
    raw_of= boost::shared_array<char> (new char[size]);
    ofh = (ofp_header*) raw_of.get();
    bzero(ofh, size);
    //TODO: also send fm command to remove all flows. 
    ofh->version = OFP_VERSION;
    ofh->type = OFPT_BARRIER_REQUEST;
    ofh->length = htons(size);
    for(it = this->registered_datapath.begin() ; it < this->registered_datapath.end() ; it++) {
      send_openflow_command(**it, ofh, false);
    }

    /*if(this->ip_mapping.find(state->ip) != this->ip_mapping.end()) {
      del_addr(ntohl(state->ip) + 1);
      this->ip_mapping.erase(state->ip);
    }
    
    if(this->mac_mapping.find(state->mac) != this->mac_mapping.end()) 
      this->mac_mapping.erase(state->mac);
    delete state;*/
    
  }

  /////////////////////////////////////////////
  //   Netlink interaction methods
  ////////////////////////////////////////////
  bool 
  dhcp::add_addr(uint32_t ip) {
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
    int ret = rtnl_addr_add(sk, addr, 0);
    if( (ret < 0) && ( abs(ret) != NLE_EXIST)) {
      nl_perror(ret, "addr_set_local");
      exit(1);
    }
    return 1;
    // Free the memory
    //nl_addr_destroy(local_addr);
    rtnl_addr_put(addr);    
  }

  bool 
  dhcp::del_addr(uint32_t ip) {
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


  /////////////////////////////////////
  //   Packet generation methods
  /////////////////////////////////////
  bool 
  dhcp::send_flow_modification (Flow flow, uint32_t wildcard,  datapathid datapath_id,
                uint32_t buffer_id, uint16_t command, uint16_t timeout,
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
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
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

  size_t
  dhcp::generate_dhcp_reply(uint8_t **ret, struct dhcp_packet  * dhcp, 
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
    if((dhcp_msg_type == DHCPNAK) ||
       ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, ipaddr(send_ip))) { 
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

  REGISTER_COMPONENT(Simple_component_factory<dhcp>,
             dhcp);

  bool
  dhcp::extract_headers(uint8_t *data, uint32_t data_len, struct nw_hdr *hdr) {
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

} // vigil namespace
