#include "dhcp.hh"
#include "dhcp_proxy.hh"

#include <map>
#include <utility>      
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

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

//#include "local_addr.hh"

#define BRIDGE_INTERFACE_NAME "br0"

#define MAX_ROUTABLE_LEASE_DURATION 1800
#define MAX_NON_ROUTABLE_LEASE_DURATION 30

#define ROUTABLE_SUBNET "10.2.0.0"
#define ROUTABLE_NETMASK 16

#define NON_ROUTABLE_SUBNET "10.3.0.0"
#define NON_ROUTABLE_NETMASK 16

#define MAX_IP_LEN 32

#define FLOW_TIMEOUT_DURATION 10

const char *dhcp_msg_type_name[] = {NULL, "DHCPDiscover", "DHCPOffer", 
				    "DHCPRequest", "DHCPDecline", "DHCPAck", 
				    "DHCPNak", "DHCPRelease", "DHCPInform"};


//check uhdhcp

inline void generate_openflow_dhcp_flow(ofp_flow_mod* ofm, size_t size);

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

    /* display result */
    printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	   (unsigned char)ifr.ifr_hwaddr.sa_data[0],
	   (unsigned char)ifr.ifr_hwaddr.sa_data[1],
	   (unsigned char)ifr.ifr_hwaddr.sa_data[2],
	   (unsigned char)ifr.ifr_hwaddr.sa_data[3],
	   (unsigned char)ifr.ifr_hwaddr.sa_data[4],
	   (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
    
    memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    
    this->bridge_mac = ethernetaddr(addr);
    printf("br0 mac addr : %s\n", this->bridge_mac.string().c_str());
    close(s);
  }


  
  void dhcp::install() {
    lg.dbg(" Install called ");
    //register_handler<Packet_in_event>(boost::bind(&dhcp::packet_in_handler, this, _1));

    Packet_expr expr;
    uint32_t val = ethernet::IP;
    expr.set_field(Packet_expr::DL_TYPE,  &val);
    val = ip_::proto::UDP;
    expr.set_field(Packet_expr::NW_PROTO, &val);
    // val = 67;
    // expr.set_field(Packet_expr::TP_DST, &val);
    // val = 68;
    // expr.set_field(Packet_expr::TP_SRC, &val);
    printf("dhcp rule: %s\n", expr.to_string().c_str());
    register_handler_on_match(1, expr,boost::bind(&dhcp::dhcp_handler, this, _1));
    expr = Packet_expr();
    val = ethernet::ARP;
    expr.set_field(Packet_expr::DL_TYPE,  &val);
    printf("arp rule: %s\n", expr.to_string().c_str());
    register_handler_on_match(2, expr,boost::bind(&dhcp::arp_handler, this, _1));
    expr = Packet_expr();
    val = ethernet::IP;
    expr.set_field(Packet_expr::DL_TYPE,  &val);
    printf("packet in rule: %s\n", expr.to_string().c_str());
    register_handler_on_match(10, expr,boost::bind(&dhcp::packet_in_handler, this, _1));
    val = ethernet::PAE;
    expr.set_field(Packet_expr::DL_TYPE,  &val);
    printf("packet in rule: %s\n", expr.to_string().c_str());
    register_handler_on_match(10, expr,boost::bind(&dhcp::pae_handler, this, _1));
 
    register_handler<Datapath_join_event>(boost::bind(&dhcp::datapath_join_handler, this, _1));
    register_handler<Datapath_leave_event>(boost::bind(&dhcp::datapath_leave_handler, this, _1));
    timeval tv = {1,0};
    //post(boost::bind(&dhcp::refresh_default_flows, this), tv);
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
    for(it = this->registered_datapath.begin(); it < this->registered_datapath.end(); it++) {
      generate_openflow_dhcp_flow(ofm, size);
      send_openflow_command(**it, &ofm->header, true);
    }
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
    ofp_flow_mod* ofm;
    size_t size = sizeof *ofm + sizeof(ofp_action_output);
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();

    generate_openflow_dhcp_flow(ofm, size);
    send_openflow_command(pi.datapath_id, &ofm->header, true);
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
    uint32_t buffer_id = pi.buffer_id;

    ofp_flow_mod* ofm;
    size_t size = sizeof(*ofm) + 2*sizeof(ofp_action_output);
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards =htonl(~OFPFW_DL_TYPE);
    ofm->match.in_port = htons(flow.in_port);
    ofm->match.dl_type = ethernet::ARP; //flow.dl_type;
    ofm->cookie = htonl(0);
    ofm->command = htons(OFPFC_ADD);
    ofm->buffer_id = htonl(buffer_id);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons( OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP);
    ofp_action_output& action_local = *((ofp_action_output*)(ofm->actions)); 
    memset(&action_local, 0, sizeof(ofp_action_output));
    action_local.type = htons(OFPAT_OUTPUT);
    action_local.len = htons(sizeof(ofp_action_output));
    action_local.port = 0; 
    action_local.max_len = htons(2000);
    ofp_action_output& action_remote = *((ofp_action_output*)(ofm->actions) + 1); 
    memset(&action_remote, 0, sizeof(ofp_action_output));
    action_remote.type = htons(OFPAT_OUTPUT);
    action_remote.len = htons(sizeof(ofp_action_output));
    action_remote.port = htons(1); 
    action_remote.max_len = htons(2000);

    send_openflow_command(pi.datapath_id, &ofm->header, true);
    return STOP;
  }

  Disposition dhcp::pae_handler(const Event& e) {
    // chrck for better handling ioctrl and SIOCSARP
    // it will allow to insert mac entries programmatically
    // so that you can always control what is going on in the net.
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    printf("eap received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
    	   flow.dl_type , flow.nw_proto);
    
    if(flow.dl_src == ethernetaddr("00:25:d3:72:b5:1e")) {
      printf("Skipping eap packet from 00:25:d3:72:b5:1e\n");
      return STOP;
    }
    
    uint32_t buffer_id = pi.buffer_id;
    ofp_flow_mod* ofm;
    size_t size = sizeof(*ofm) + sizeof(ofp_action_output);
    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards =htonl(~(OFPFW_IN_PORT | OFPFW_DL_SRC | OFPFW_DL_TYPE));
    ofm->match.in_port = htons(flow.in_port);
    ofm->match.dl_type = flow.dl_type; 
    memcpy(ofm->match.dl_src, flow.dl_src.octet, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow.dl_dst.octet, sizeof ofm->match.dl_dst);
    ofm->cookie = htonl(0);
    ofm->command = htons(OFPFC_ADD);
    ofm->buffer_id = htonl(buffer_id);
    ofm->idle_timeout = htons(1);//htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(1);//htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons( OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP);
    ofp_action_output& action_local = *((ofp_action_output*)(ofm->actions)); 
    memset(&action_local, 0, sizeof(ofp_action_output));
    action_local.type = htons(OFPAT_OUTPUT);
    action_local.len = htons(sizeof(ofp_action_output));
    action_local.port = 0; 
    action_local.max_len = htons(2000);
    send_openflow_command(pi.datapath_id, &ofm->header, true);
    return STOP;
  }
  
  Disposition 
  dhcp::packet_in_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    uint32_t buffer_id = pi.buffer_id;
    ethernetaddr dl_dst;
    dhcp_mapping *src_state = NULL, *dst_state = NULL;
    bool is_src_router = (flow.in_port == OFPP_LOCAL);
    bool is_dst_router = (flow.dl_dst == this->bridge_mac);
    bool is_dst_local = 0;
    bool is_src_local = 0;
    int dst_port = 0;

    printf("Pkt in received: %s(type:%x, proto:%x) %s->%s\n", pi.get_name().c_str(), 
	   flow.dl_type, flow.nw_proto, flow.dl_src.string().c_str(), 
	   flow.dl_dst.string().c_str());

    //check if src ip is routable and the src mac address is permitted.
    if(ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, 
		    ipaddr(ntohl(flow.nw_src))) ) {
      printf("src ip %s is not routable. Better wait to get proper ip.\n", 
	     ipaddr(ntohl(flow.nw_src)).string().c_str());
      return STOP;
    }

    //check if dst ip is routable and we have a mac address for it.
    if(ip_matching(ipaddr(NON_ROUTABLE_SUBNET), NON_ROUTABLE_NETMASK, 
		   ipaddr(ntohl(flow.nw_dst))) ) {
      printf("dst ip %s is not routable.\n", ipaddr(ntohl(flow.nw_dst)).string().c_str());
      return STOP;
    }


    //check if src ip is routable and the src mac address is permitted.
    if( (!is_src_router) && 
       (!this->p_dhcp_proxy->is_ether_addr_routable(flow.dl_src)) ) {
      printf("MAC address %s is not permitted to send data\n", flow.dl_src.string().c_str());
      return STOP;
    }

    // find state for source - in case the address comes 
    // from the server ignore state rquirement. 
    is_src_local = ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, ipaddr(ntohl(flow.nw_src)));

    if(!is_src_router) {
      if((this->mac_mapping.find(flow.dl_src) == this->mac_mapping.end())  || 
	 ((src_state = this->mac_mapping[flow.dl_src]) == NULL) ){
	printf("No state found for source mac\n");
	return STOP;
      }  
      if( src_state->ip != flow.nw_src ){
	printf("Source hosts uses unassigned ip address\n");
	return STOP;
      }
    } else if(flow.dl_src != this->bridge_mac) {
      printf("received packet from bridge without correct mac. discarding\n");
      return STOP;
    }


    //checkin proper output port by checkin the dst mac and ip
    if(ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, 
		   ipaddr(ntohl(flow.nw_dst))) ) {
      //printf("check mac %s\n", (flow.dl_dst == this->bridge_mac)?"yes":"no");
      //printf("check ip %s\n", (this->ip_mapping.find(ipaddr(ntohl(flow.nw_dst) - 1)) != this->ip_mapping.end())?"yes":"no");
      //required assumption for  packet destined to the bridged intf. 
      if((flow.dl_dst == this->bridge_mac) && 
	 (this->ip_mapping.find(ipaddr(htonl(flow.nw_dst) - 1)) != this->ip_mapping.end())) {
	dst_port = 0;
	//reuired properties for a packet to be destined to one of the internal hosts.
      } else if ( (this->ip_mapping.find(ipaddr(ntohl(flow.nw_dst))) != this->ip_mapping.end()) ) {
	//output to port 1
	dst_port = 1;
      } else {
	printf("destination mac and ip where incorrect.\n");
	return STOP;
      }
    } else 
      dst_port = 0;

    is_dst_local = ip_matching(ipaddr(ROUTABLE_SUBNET), ROUTABLE_NETMASK, ipaddr(ntohl(flow.nw_dst)));


    // if ( (!is_dst_router) && 
    // 	(this->ip_mapping.find(ipaddr(ntohl(flow.nw_dst))) ==  this->ip_mapping.end())) {
    //   printf("dst ip %s is not found.\n", ipaddr(ntohl(flow.nw_dst)).string().c_str());
    //   return STOP;
    // }
    // if ((!is_dst_router) && (this->ip_mapping[ipaddr(ntohl(flow.nw_dst))] == NULL)) {
    //   printf("dst ip %s is found but has no state.\n", 
    // 	     ipaddr(ntohl(flow.nw_dst)).string().c_str());
    //   return STOP;
    // } else if ((!is_dst_router) && (this->ip_mapping[ipaddr(ntohl(flow.nw_dst))] != NULL)){
    //   dl_dst = this->ip_mapping[ipaddr(ntohl(flow.nw_dst))]->mac;
    // }

    ofp_flow_mod* ofm;
    size_t size = sizeof(*ofm) + sizeof(ofp_action_output);
    if(is_dst_local && is_src_local && (dst_port != 0) && (!is_src_router))
      size += 2*sizeof( ofp_action_dl_addr);

    boost::shared_array<char> raw_of(new char[size]);
    ofm = (ofp_flow_mod*) raw_of.get();
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->match.wildcards = htonl(0);
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
    ofm->command = htons(OFPFC_ADD);
    ofm->buffer_id = htonl(buffer_id);
    ofm->idle_timeout = htons(5);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons( OFPFF_SEND_FLOW_REM | OFPFF_CHECK_OVERLAP);
    if(is_dst_local && is_src_local && (dst_port != 0) && (!is_src_router)) {
      //      ofp_action_dl_addr& act_dl_src = *((ofp_action_dl_addr*)(((void *)ofm->actions) + 8)); 
      ofp_action_dl_addr& act_dl_src = *((ofp_action_dl_addr*)(ofm->actions)); 
      memset(&act_dl_src, 0, sizeof(ofp_action_dl_addr));
      act_dl_src.type = htons(OFPAT_SET_DL_SRC);
      act_dl_src.len = htons(sizeof(ofp_action_dl_addr));
      memcpy(act_dl_src.dl_addr, (const uint8_t *)this->bridge_mac, sizeof act_dl_src.dl_addr);
      ofp_action_dl_addr& act_dl_dst = *((ofp_action_dl_addr*)(ofm->actions + 2)); 
      memset(&act_dl_dst, 0, sizeof(ofp_action_dl_addr));
      act_dl_dst.type = htons(OFPAT_SET_DL_DST);
      act_dl_dst.len = htons(sizeof(ofp_action_dl_addr));
      printf("dest mac : %s\n", this->ip_mapping[ipaddr(ntohl(flow.nw_dst))]->mac.string().c_str());
      memcpy(act_dl_dst.dl_addr, (const uint8_t *)this->ip_mapping[ipaddr(ntohl(flow.nw_dst))]->mac, sizeof act_dl_dst.dl_addr);
      ofp_action_output& action = *((ofp_action_output*)(ofm->actions + 4)); 
      memset(&action, 0, sizeof(ofp_action_output));
      action.type = htons(OFPAT_OUTPUT);
      action.len = htons(sizeof(ofp_action_output));
      action.max_len = htons(2000);    
      action.port = (dst_port == flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port); //dst_port); 
    } else {
      ofp_action_output& action = *((ofp_action_output*)(ofm->actions)); 
      memset(&action, 0, sizeof(ofp_action_output));
      action.type = htons(OFPAT_OUTPUT);
      action.len = htons(sizeof(ofp_action_output));
      action.max_len = htons(2000);    
      action.port = (dst_port == flow.in_port)?htons(OFPP_IN_PORT):htons(dst_port); //htons(OFPP_IN_PORT); //dst_port);
    }


    send_openflow_command(pi.datapath_id, &ofm->header, true);
    return CONTINUE;
  }
  
  Disposition dhcp::dhcp_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    //printf("dhcp received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
    //	   flow.dl_type , flow.nw_proto);

    // if((flow.dl_type != 0x0008) ||             //packet is ethernet
    //    (flow.nw_proto != 17)               //packet is UDP
    //    ) {                 
    //   return CONTINUE;
    // } 

    // for some reason events are only fired for this action when nox 
    // sees udp traffic. 
    if( (ntohs(flow.tp_dst) != 67) || (ntohs(flow.tp_src) != 68)) {
      printf("This is nor DHCP traffic!\n");
      this->packet_in_handler(e);
      return CONTINUE;
    }  
    
    uint8_t *data = pi.get_buffer()->data(), *reply = NULL;
    int32_t data_len = pi.get_buffer()->size();
    int pointer = 0;

    if(data_len < sizeof( struct ether_header))
      return CONTINUE;
    
    // parse ethernet header
    struct ether_header *ether = (struct ether_header *) data;
    pointer += sizeof( struct ether_header);
    data_len -=  sizeof( struct ether_header);
    
    // parse ip header
    if(data_len < sizeof(struct iphdr))
      return CONTINUE;
    struct iphdr *ip = (struct iphdr *) (data + pointer);
    if(data_len < ip->ihl*4) 
      return CONTINUE;
    pointer += ip->ihl*4;
    data_len -= ip->ihl*4;

    //parse udp header
    struct udphdr *udp = (struct udphdr *)(data + pointer);
    pointer += sizeof(struct udphdr);
    data_len -= sizeof(struct udphdr);
    uint16_t dhcp_len = ntohs(udp->len) - sizeof(struct udphdr);
    
    struct dhcp_packet *dhcp = (struct dhcp_packet  *)(data + pointer);

    //analyse options and reply respectively.
    data_len -= sizeof(struct dhcp_packet);
    pointer +=  sizeof(struct dhcp_packet);

    //get the exact message type of the dhcp request
    uint8_t dhcp_msg_type = 0;
    uint32_t requested_ip = 0;
    while(data_len > 2) {
      uint8_t dhcp_option = data[pointer];
      uint8_t dhcp_option_len = data[pointer+1];
      //printf("pointer:%d, cookie:%llx, option %02x, len:%02x, option %02x, len:%02x\n", 
      //pointer,(long long unsigned int)dhcp->cookie, data[pointer], data[pointer+1], 
      // dhcp_option, dhcp_option_len);
      
      
      if(dhcp_option == 0xff) {
      	printf("Got end of options!!!!\n");
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
	//printf("dhcp msg type : %s\n", dhcp_msg_type_name[dhcp_msg_type]);
	}
    
      data_len -=(2 + dhcp_option_len );
      pointer +=(2 + dhcp_option_len );
    }
    //Must create a fucntion that chooses this ip for the state of the DHCP server. 
    ipaddr send_ip = this->select_ip(ethernetaddr(ether->ether_shost), dhcp_msg_type);
    bool is_routable =this->ip_matching(ipaddr(ROUTABLE_SUBNET),ROUTABLE_NETMASK, ntohl((uint32_t)send_ip));

    //TODO: if ip is routable, add ip to the interface
    if(is_routable) {
      this->add_addr(ntohl((uint32_t)send_ip) + 1);
    } else {
      printf("ip %s is not routable\n", send_ip.string().c_str());
    }

    uint8_t reply_msg_type = (dhcp_msg_type == DHCPDISCOVER?DHCPOFFER:DHCPACK);
    
    if( (requested_ip != 0)  &&
	((dhcp_msg_type == DHCPREQUEST) && (requested_ip != (uint32_t)send_ip))){
      struct in_addr in;
      in.s_addr = send_ip;
      printf("DHCPNACK: requested ip differ from send_ip %s\n", inet_ntoa(in));
      reply_msg_type = DHCPNAK;
    }

    // if((requested_ip != 0) && (send_ip != requested_ip) && 
    //    (reply_msg_type == DHCPREQUEST) ) {
    //   struct in_addr in;
    //   in.s_addr = send_ip;
    //   printf("DHCPREQUEST but send_ip %s different from requested %d\n", inet_ntoa(in));
    //   reply_msg_type = DHCPNCK;
    // }
    size_t len = generate_dhcp_reply(&reply, dhcp, dhcp_len, &flow, 
				     ntohl((uint32_t)send_ip), reply_msg_type, 
				     is_routable?MAX_ROUTABLE_LEASE_DURATION:MAX_NON_ROUTABLE_LEASE_DURATION);

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

    //run out of avaiiliable ip
    if((ip&(0xFFFFFFFF<<netmask))!=ntohl(subnet)) {
      return 0; //return zero if no availiable ip found
    }
    return ip;
  }

  ipaddr 
  dhcp::select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type) {
    map<struct ethernetaddr, struct dhcp_mapping *>::iterator iter_ether;
    struct dhcp_mapping *state;
    bool is_routable;
    uint32_t ip = 0;
    timeval tv;
    time_t lease_end = 0;

    gettimeofday(&tv, NULL);
    lease_end = tv.tv_sec;

    printf("looking mac %s with dhcp msg type : (%d) %s\n", 
	   ether.string().c_str(), dhcp_msg_type, dhcp_msg_type_name[dhcp_msg_type]);
    
    //firstly check if the mac address is aloud access
    is_routable = this->check_access(ether); 
    lease_end +=(is_routable)?MAX_ROUTABLE_LEASE_DURATION:MAX_NON_ROUTABLE_LEASE_DURATION;
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
      if(!ip_matching(ipaddr((is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET)), 
		     ((is_routable)? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK), state->ip)) {
	printf("ip assingment is invalid!\n");	

	//remove old mapping
	if(this->ip_mapping.find(state->ip) != this->ip_mapping.end())
	  this->ip_mapping.erase(state->ip);
	if(this->mac_mapping.find(state->mac) != this->mac_mapping.end()) 
	  this->mac_mapping.erase(state->mac);
	delete state;

	//generate new mapping
	ip = find_free_ip(ipaddr(is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET), 
			  is_routable? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK);

	printf("lease end: %ld %ld\n",  tv.tv_sec, lease_end);
	ip++;
	state = new dhcp_mapping(ipaddr(ip), ether, lease_end);
	//printf("inserting new entry for %s - %s\n", ether.string().c_str(), 
	//state->string().c_str());
	this->mac_mapping[ether] = state;
	this->ip_mapping[ipaddr(ip)] = state;
      }
    } else {
      //check whether you might need to delete some old mapping on the ip map.
      ip = find_free_ip(ipaddr(is_routable? ROUTABLE_SUBNET: NON_ROUTABLE_SUBNET), 
			is_routable? ROUTABLE_NETMASK: NON_ROUTABLE_NETMASK);
      if(!ip) {
	printf("run out of ip's - no reply\n");
	return STOP;
      }
      ip++;

      //create state with new ip and send it out.
      printf("lease end:%ld %ld\n",  tv.tv_sec, lease_end);
      state = new dhcp_mapping(ipaddr(ip), ether, lease_end);
      //printf("inserting new entry for %s - %s\n", ether.string().c_str(), 
      //	     state->string().c_str());
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

  bool 
  dhcp::check_access(const ethernetaddr& ether) {
    return this->p_dhcp_proxy->is_ether_addr_routable(ether);
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

    if(this->ip_mapping.find(state->ip) != this->ip_mapping.end()) {
      del_addr(ntohl(state->ip) + 1);
      this->ip_mapping.erase(state->ip);
    }
    
    if(this->mac_mapping.find(state->mac) != this->mac_mapping.end()) 
      this->mac_mapping.erase(state->mac);
    delete state;
    
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
    local_addr->a_prefixlen = 30;
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
    local_addr->a_prefixlen = 30;
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

    struct dhcp_packet  *reply = (struct dhcp_packet *)(*ret + 
							sizeof(struct ether_header) + 
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
    // if this is a NAK, we don't need to set the other fields
    if(dhcp_msg_type == DHCPNAK) {
      options[0] = 0xff; 
      return len;
    }
   
    //netmask 
    options[0] = 1;
    options[1] = 4;
    *((uint32_t *)(options + 2)) = htonl(0xFFFFFFFC); 
    options += 6;
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
    //lease_time
    options[0] = 51;
    options[1] = 4;
    *((uint32_t *)(options + 2)) = htonl(lease); 
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

} // vigil namespace

inline void 
generate_openflow_dhcp_flow(ofp_flow_mod* ofm, size_t size) {
  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(size);
  ofm->match.wildcards = htonl(OFPFW_IN_PORT | OFPFW_DL_VLAN | 
			       OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS |  OFPFW_DL_SRC |  
			       OFPFW_DL_DST | (OFPFW_NW_SRC_ALL) | (OFPFW_NW_DST_ALL));

  printf("netmask : %lX\n", ofm->match.wildcards);
  
  ofm->match.dl_type = htons(0x0800);
  //ofm->match.nw_src = inet_addr("0.0.0.0");
  //ofm->match.nw_dst =  inet_addr("255.255.255.255");
  ofm->match.nw_proto = 17;
  ofm->match.tp_src = htons(68);
  ofm->match.tp_dst = htons(67);
  ofm->cookie = htonl(0);
  ofm->command = htons(OFPFC_ADD);
  ofm->buffer_id = -1;
  ofm->idle_timeout =  OFP_FLOW_PERMANENT;
  ofm->hard_timeout =  OFP_FLOW_PERMANENT;
  ofm->priority = htons(OFP_DEFAULT_PRIORITY);
  ofm->flags = htons(0);
  ofp_action_output& action = *((ofp_action_output*)ofm->actions);
  memset(&action, 0, sizeof(ofp_action_output));
  action.type = htons(OFPAT_OUTPUT);
  action.len = htons(sizeof(ofp_action_output));
  action.port = htons(OFPP_CONTROLLER);
  //stupid fix. normally size 0 means all, but openvswitch disagrees.
  action.max_len = htons(2000);
}
