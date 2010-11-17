#include "dhcp.hh"

#include <boost/bind.hpp>
#include <boost/shared_array.hpp>
#include <map>
#include <utility>
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
#include "netinet++/ipaddr.hh"

#define MAX_ROUTABLE_LEASE_DURATION 30
#define MAX_NON_ROUTABLE_LEASE_DURATION 30

#define ROUTABLE_SUBNET "10.2.0.0"
#define ROUTABLE_NETMASK 16
#define MAX_IP_LEN 32

#define NON_ROUTABLE_SUBNET "10.3.0.0"
#define NON_ROUTABLE_NETMASK 16

#define FLOW_TIMEOUT_DURATION 10

const char *dhcp_msg_type_name[] = {NULL, "DHCPDiscover", "DHCPOffer", 
				    "DHCPRequest", "DHCPDecline", "DHCPAck", 
				    "DHCPNak", "DHCPRelease", "DHCPInform"};

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

  bool 
  dhcp::check_access(const ethernetaddr& ether) {
    return true;
  }

  ipaddr 
  dhcp::select_ip(const ethernetaddr& ether, uint8_t dhcp_msg_type) {
    map<struct ethernetaddr, struct dhcp_mapping *>::iterator iter_ether;
    map<struct ipaddr, struct dhcp_mapping *>::iterator iter_ip;
    struct dhcp_mapping *state;
    bool is_routable;
    uint32_t ip = 0 ;
    uint32_t max_ip = 0;
    uint32_t len = 0;
    uint32_t inc = 4;
    int i;
    timeval tv;

    printf("looking mac %s with dhcp msg type : %s\n", 
	   ether.string().c_str(), dhcp_msg_type_name[dhcp_msg_type]);
    
    //firstly check if the mac address is aloud access
    is_routable = this->check_access(ether); 
    //check now if we can find the MAC in the list 
    if( (iter_ether = this->mac_mapping.find(ether)) != this-> mac_mapping.end()) {
      state = iter_ether->second;
      printf("found mapping for addr %s -> %s\n", ether.string().c_str(), state->string().c_str());
    } else {
      //find a free ip
      gettimeofday(&tv, NULL);

      if(is_routable) {
	ip = ntohl(inet_addr(ROUTABLE_SUBNET));
	len = ROUTABLE_NETMASK;
      } else {
	ip = ntohl(inet_addr(NON_ROUTABLE_SUBNET));
	len = NON_ROUTABLE_NETMASK;
      }
      for( i = 0; i < (MAX_IP_LEN - len - 2); i++)
	max_ip = (max_ip << 1) + 1;
      //the last two bits are kept in case for the subnetting of the localnetowkr 
      max_ip = (max_ip << 2);
      max_ip = max_ip | ip;
      for (; ip <= max_ip; ip += inc) {
	if((iter_ip = this->ip_mapping.find(ipaddr(ip))) == this->ip_mapping.end())
	  break;
	
	//if the lease has ended for less than 30 minutes then keep the mapping just in case
	if( tv.tv_sec - iter_ip->second->lease_end > 30*60 )
	  continue;
	
	//if everything above passed then we have to kick this mapping for the next device
	ethernetaddr ether = iter_ip->second->mac;
	delete iter_ip->second;
	this->ip_mapping.erase(ip);
	if(this->mac_mapping.find(ether) != this->mac_mapping.end()) {
	  this->mac_mapping.erase(ether);
	}
	break;
      }
      
      if(ip > max_ip) {
	printf("wtf!!!! run out of ip's????\n");
	exit(1);
      }

      //check whether you might need to delete some old mapping on the ip map.
      
      //create state with new ip and send it out.
      state = new dhcp_mapping(ipaddr(ip), ether, tv.tv_sec + (is_routable)?
			       MAX_ROUTABLE_LEASE_DURATION:MAX_NON_ROUTABLE_LEASE_DURATION);
      printf("inserting new entry for %s - %s\n", ether.string().c_str(), state->string().c_str());
      this->mac_mapping[ether] = state;
      this->ip_mapping[ipaddr(ip)] = state;
      //I need to find here the appropriate ip addr
    } 
    ip+=1;
    return ipaddr(ip);
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

    uint8_t dhcp_msg_type = 0;
    while(data_len > 2) {
      uint8_t dhcp_option = data[pointer];
      uint8_t dhcp_option_len = data[pointer+1];
      //printf("pointer:%d, cookie:%llx, option %02x, len:%02x, option %02x, len:%02x\n", pointer,  
      //	     (long long unsigned int)dhcp->cookie, data[pointer], data[pointer+1],  dhcp_option,  
      //	     dhcp_option_len);
      
      if(dhcp_option == 53) {
	dhcp_msg_type = data[pointer + 2];
	if((dhcp_msg_type <1) || (dhcp_msg_type > 8)) {
	  printf("Invalid DHCP Message Type : %d\n", dhcp_msg_type);
	  return STOP;
	}
	//printf("dhcp msg type : %s\n", dhcp_msg_type_name[dhcp_msg_type]);
	break;
      }
      if(dhcp_option == 0xff) {
      	printf("Got end of options!!!!\n");
     	break;
      }
      data_len -=(2 + dhcp_option_len );
      pointer +=(2 + dhcp_option_len );
    }
    //Must create a fucntion that chooses this ip for the state of the DHCP server. 
    //uint32_t send_ip = htonl(inet_addr("10.1.1.1"));

    ipaddr send_ip = this->select_ip(ethernetaddr(ether->ether_shost), dhcp_msg_type);

    uint8_t reply_msg_type = (dhcp_msg_type == DHCPDISCOVER? 
			      DHCPOFFER:DHCPACK);

    size_t len = generate_dhcp_reply(&reply, dhcp, dhcp_len, &flow, 
				     send_ip, reply_msg_type);
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
  dhcp::generate_dhcp_reply(uint8_t **ret, struct dhcp_packet  * dhcp, 
			    uint16_t dhcp_len, Flow *flow, uint32_t send_ip,
			    uint8_t dhcp_msg_type) {
    //uint8_t *ret = NULL;
    int len =  sizeof( struct ether_header) + sizeof(struct iphdr) + 
      sizeof(struct udphdr) + sizeof(struct dhcp_packet) + 3 + 6 + 6 + 6 + 6 + 6 + 1;
    //message_type + netmask + router + nameserver + lease_time + end option
    //lease time is seconds since it will timeout

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
    reply->yiaddr = (uint32_t)htonl(send_ip); //inet_addr("10.2.0.2");
    reply->siaddr =  (uint32_t)htonl(send_ip + 1); //inet_addr("10.2.0.1"); 
    memcpy(reply->chaddr, (const uint8_t *)flow->dl_src, 6);
    reply->cookie =  dhcp->cookie; //inet_addr("10.2.0.1"); 

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
    *((uint32_t *)(options + 2)) = htonl(30); 
    options += 6;
    //router 
    options[0] = 54;
    options[1] = 4;
    *((uint32_t *)(options + 2)) = htonl(send_ip+1); 
    options += 6;
    //set end of options
    options[0] = 0xff;
    

    //analyse options and reply respectively.
    // uint8_t *data = (dhcp->options - 1);
    // uint16_t  data_len = dhcp_len - sizeof(struct dhcp_packet);
    // uint16_t pointer = 1;
    // while(data_len > 0) {
    //   uint8_t dhcp_option = data[pointer];
    //   uint8_t dhcp_option_len = data[pointer+1];
    //   printf("cookie:%llx, option %x, len:%x\n", (long long unsigned int)dhcp->cookie, 
    // 	     dhcp_option, dhcp_option_len);
    //   pointer +=(2 + dhcp_option_len);
    //   data_len -=(2 + dhcp_option_len);
    //   if(dhcp_option_len == 0) {
    // 	printf("Got an option with zero length!!!!\n");
    // 	break;
    //   }
    // }

    return len;

  }

  std::list<dhcp_mapping> 
  get_dhcp_mappings() {
    
  }

  std::string
  dhcp::hello_world() {
    return string("Hello World!!!");
  }

  REGISTER_COMPONENT(Simple_component_factory<dhcp>,
		     dhcp);
  //-------------------------
  // dhcp_mapping implementation
  //-------------------------
  inline
  dhcp_mapping::dhcp_mapping(const dhcp_mapping& in) {
    ip=in.ip;
    mac = in.mac;
    lease_end = in.lease_end;
  }
  
  inline
  dhcp_mapping::dhcp_mapping(const  ipaddr& _ip, const  ethernetaddr& _mac, uint32_t _lease_end) {
    ip = _ip;
    mac = _mac;
    lease_end = _lease_end;
  }

  inline
  std::string 
  dhcp_mapping::string() const{
    //max uint32_t has 9 decimal digits
    uint16_t str_len = sizeof("255.255.255.255 FF:FF:FF:FF:FF:FF XXXXXXXXXX");
    char  buf[str_len];
    
    snprintf(buf, str_len, "%s %s %llu", ip.string().c_str(), mac.string().c_str(), 
	     (long long unsigned int)lease_end);
    
    return std::string(buf);
  }

  inline bool 
  dhcp_mapping::operator == (const dhcp_mapping& dhcp) const {
    return ((dhcp.ip == this->ip) && (dhcp.mac == this->mac) ); //&& (dhcp.lease_end == this.lease_end) );
    
  }
  inline bool 
  dhcp_mapping::operator == (const ethernetaddr& mac) const {
    return (mac == this->mac);
  }
  inline bool 
  dhcp_mapping::operator == (const ipaddr& ip) const {
   return (ip == this->ip);    
  }
  
  // inline bool 
  // dhcp_mapping::operator == (const ipaddr&, const ethernetaddr&) const {
  //   return ((dhcp.ip == ip) && (dhcp.mac == mac));
  // }

} // vigil namespace

inline void 
generate_openflow_dhcp_flow(ofp_flow_mod* ofm, size_t size) {
  ofm->header.version = OFP_VERSION;
  ofm->header.type = OFPT_FLOW_MOD;
  ofm->header.length = htons(size);
  ofm->match.wildcards = htonl(OFPFW_IN_PORT |  OFPFW_DL_VLAN | 
			       OFPFW_DL_VLAN_PCP | OFPFW_NW_TOS |  OFPFW_DL_SRC |  
			       OFPFW_DL_DST | OFPFW_NW_SRC_ALL);
  ofm->match.dl_type = htons(0x0800);
  //ofm->match.nw_src = inet_addr("0.0.0.0");
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
