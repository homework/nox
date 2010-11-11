#include "dhcp.hh"

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "packet-in.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "vlog.hh"

#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"

#define FLOW_TIMEOUT_DURATION 10

//check uhdhcp

inline void generate_openflow_dhcp_flow(ofp_flow_mod* ofm, size_t size);

namespace vigil
{
  static Vlog_module lg("dhcp");

  void dhcp::configure(const Configuration* c) {
    lg.dbg(" Configure called ");
  }

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

  Disposition dhcp::packet_in_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    printf("Event received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
	   flow.dl_type , flow.nw_proto);

    if((flow.dl_type != 0x0008) ||             //packet is ethernet
       (flow.nw_proto != 17)               //packet is UDP
       ) {                 
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

    if(ip->protocol != 17) {
      printf("Not UDP");
      return CONTINUE;
    }

    //parse udp header
    struct udphdr *udp = (struct udphdr *)(data + pointer);
    if( (ntohs(udp->dest) != 67) || (ntohs(udp->source) != 68)) {
      printf("This is nor DHCP traffic!\n");
      return CONTINUE;
    }  
    pointer += sizeof(struct udphdr);
    data_len -= sizeof(struct udphdr);
    uint16_t dhcp_len = ntohs(udp->len) - sizeof(struct udphdr);
    
    struct dhcp_packet *dhcp = (struct dhcp_packet  *)(data + pointer);

    //analyse options and reply respectively.
    data_len -= sizeof(struct dhcp_packet);
    pointer +=  sizeof(struct dhcp_packet);
    while(data_len > 2) {
      uint8_t dhcp_option = data[pointer];
      uint8_t dhcp_option_len = data[pointer+1];
      printf("pointer:%d, option %02x, len:%02x, option %02x, len:%02x\n", pointer, 
	     data[pointer], data[pointer+1],  dhcp_option,  dhcp_option_len );
      data_len -=(2 + dhcp_option_len );
      pointer +=(2 + dhcp_option_len );
      
      if(dhcp_option == 0xff) {
      	printf("Got end of options!!!!\n");
     	break;
      }
    }

    size_t len = generate_dhcp_reply(&reply, dhcp, dhcp_len, &flow);
    send_openflow_packet(pi.datapath_id, Array_buffer(reply, len), 
			 OFPP_IN_PORT, pi.in_port, 1);

    return STOP;
  }
  
  void dhcp::install() {
    lg.dbg(" Install called ");
    register_handler<Packet_in_event>(boost::bind(&dhcp::packet_in_handler, this, _1));
    register_handler<Datapath_join_event>(boost::bind(&dhcp::datapath_join_handler, this, _1));
    register_handler<Datapath_leave_event>(boost::bind(&dhcp::datapath_leave_handler, this, _1));
    timeval tv = {1,0};
    post(boost::bind(&dhcp::refresh_default_flows, this), tv);
  }
  
  void 
  dhcp::getInstance(const Context* c,
			 dhcp*& component) {
    component = dynamic_cast<dhcp*>
      (c->get_by_interface(container::Interface_description
			   (typeid(dhcp).name())));
  }

  size_t
  dhcp::generate_dhcp_reply(uint8_t **ret, struct dhcp_packet  * dhcp, uint16_t dhcp_len,
			    Flow *flow) {
    //uint8_t *ret = NULL;
    int len =  sizeof( struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_packet);
    printf("ether:%d, ip:%d, udp:%d, dhcp: %d, packet len: %d\n ", 
	   sizeof( struct ether_header), sizeof(struct iphdr),
	   sizeof(struct udphdr),  sizeof(struct dhcp_packet), len);

    //allocate space for he dhcp reply
    *ret = new uint8_t[len];
    bzero(*ret, len);
  
    //setting up ethernet header details
    struct ether_header *ether = (struct ether_header *) *ret;
    ether->ether_type = htons(ETHERTYPE_IP);
    memcpy(ether->ether_dhost, (const uint8_t *)flow->dl_src, ETH_ALEN);
    // 08:00:27:ee:1d:9f
    ether->ether_shost[0]=0x08;ether->ether_shost[1]=0x00;
    ether->ether_shost[2]=0x27; ether->ether_shost[3]=0xee;
    ether->ether_shost[4]=0x1d;ether->ether_shost[5]=0x9f;
 
    //setting up ip header details   
    struct iphdr *ip = (struct iphdr *) (*ret + sizeof(struct ether_header));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0; 
    ip->tot_len = htons(len - sizeof(struct ether_header));
    printf("ip packet len: %d\n", len - sizeof(struct ether_header));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 0x80;
    ip->protocol = 0x11;
    ip->saddr =   inet_addr("10.2.0.1"); 
    ip->daddr =  inet_addr("255.255.255.255");
    ip->check = ip_::checksum(ip, 20);

    //setting up udp header details   
    struct udphdr *udp = (struct udphdr *)(*ret + sizeof(struct ether_header) + 
					   sizeof(struct iphdr));
    udp->source = htons(67);
    udp->dest = htons(68);
    udp->len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet));
    udp->check = 0x0;

    struct dhcp_packet  *reply = (struct dhcp_packet *)(*ret + sizeof(struct ether_header) + 
							sizeof(struct iphdr) + sizeof(struct udphdr));

    reply->op = BOOTREPLY;
    reply->htype = 0x01;
    reply->hlen = 0x6;
    reply->xid = dhcp->xid;
    reply->yiaddr = (uint32_t)inet_addr("10.2.0.2");
    reply->siaddr =  (uint32_t)inet_addr("10.2.0.1"); 
    memcpy(reply->chaddr, (const uint8_t *)flow->dl_src, 6);

    //analyse options and reply respectively.
    uint8_t *data = (dhcp->options - 1);
    uint16_t  data_len = dhcp_len - sizeof(struct dhcp_packet);
  
    uint16_t pointer = 0;
    while(data_len > 0) {
      uint8_t dhcp_option = data[pointer];
      uint8_t dhcp_option_len = data[pointer+1];
      printf("cookie:%llx, option %x, len:%x\n", dhcp->cookie, dhcp_option, dhcp_option_len);
      pointer +=(2 + dhcp_option_len);
      data_len -=(2 + dhcp_option_len);
    
      if(dhcp_option_len == 0) {
    	printf("Got an option with zero length!!!!\n");
    	break;
      }
    }

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
  ofm->match.wildcards = htonl(OFPFW_IN_PORT |  OFPFW_DL_VLAN | OFPFW_DL_VLAN_PCP | 
			       OFPFW_NW_TOS |  OFPFW_DL_SRC |  OFPFW_DL_DST);
  ofm->match.dl_type = htons(0x0800);
  ofm->match.nw_src = inet_addr("0.0.0.0");
  ofm->match.nw_dst =  inet_addr("255.255.255.255");
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
