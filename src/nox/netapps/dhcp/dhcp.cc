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
#include "vlog.hh"

#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"

//check uhdhcp

namespace vigil
{
  static Vlog_module lg("dhcp");
  
  void dhcp::configure(const Configuration* c) {
    lg.dbg(" Configure called ");
    
    
  }

  Disposition dhcp::handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    //uint32_t buffer_id = pi.buffer_id;
    Flow flow(pi.in_port, *(pi.get_buffer()));
    printf("Event received: %s(type:%x, proto:%x)\n", pi.get_name().c_str(), 
	   flow.dl_type , flow.nw_proto);

    if((flow.dl_type != 0x0008) ||             //packet is ethernet
       (flow.nw_proto != 17)               //packet is UDP
       ) {                 
      return CONTINUE;
    } 
    
    uint8_t *data = pi.get_buffer()->data(), *reply = NULL;
    uint32_t data_len = pi.get_buffer()->size();
    int pointer = 0;

    if(data_len < sizeof( struct ether_header))
      return CONTINUE;
    
    // parse ethernet header
    struct ether_header *ether = (struct ether_header *) data;
    printf("ethertype %x\n", ether->ether_type);
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
    printf("ip data_len : %d\n", data_len);

    if(ip->protocol != 17) {
      printf("Not UDP");
      return CONTINUE;
    }

    //parse udp header
    struct udphdr *udp = (struct udphdr *)(data + pointer);
    printf("UDP src port : %u dst_port: %d, udp len:%d\n", ntohs(udp->source),  ntohs(udp->dest), ntohs(udp->len));
    if( (ntohs(udp->dest) != 67) || (ntohs(udp->source) != 68)) {
      printf("This is nor DHCP traffic!\n");
      return CONTINUE;
    }  
    pointer += sizeof(struct udphdr);
    data_len -= sizeof(struct udphdr);
    printf("udp data_len : %d\n", data_len);
    uint16_t dhcp_len = ntohs(udp->len) - sizeof(struct udphdr);
    
    struct dhcp_packet *dhcp = (struct dhcp_packet  *)(data + pointer);
    printf("xid : 0x%x\n", ntohl(dhcp->xid));

    printf("data_len : %d, dhcp msg size : %d\n", data_len, sizeof(struct dhcp_packet));
    //analyse options and reply respectively.
    data_len -= sizeof(struct dhcp_packet);
    pointer +=  sizeof(struct dhcp_packet);
    printf("data_len : %u, dhcp msg size : %d\n", data_len, sizeof(struct dhcp_packet));
    while(data_len > 0) {
      uint8_t dhcp_option = data[pointer];
      uint8_t dhcp_option_len = data[pointer+1];
      
      pointer +=(2 + dhcp_option_len);
      data_len -=(2 + dhcp_option_len);
      printf("pointer:%d, cookie:%llx, option %d, len:%d\n", pointer, dhcp->cookie, dhcp_option, dhcp_option_len);
      
      if(dhcp_option_len == 0) {
	printf("Got an option with zero length!!!!\n");
	break;
      }
    }

    size_t len = generate_dhcp_reply(&reply, dhcp, dhcp_len, &flow);

     // std::auto_ptr<Buffer> buf = std::auto_ptr<Buffer>(0);
     // buf->push(len);
     // memcpy(buf->data, reply, len);

     send_openflow_packet(pi.datapath_id, Array_buffer(reply, len), 
			  OFPP_IN_PORT, pi.in_port, 1);

    return STOP;
  }
  
  void dhcp::install() {
    lg.dbg(" Install called ");
    register_handler<Packet_in_event>(boost::bind(&dhcp::handler, this, _1));
  }
  
  void dhcp::getInstance(const Context* c,
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
  uint8_t *data = dhcp->options;
  uint16_t  data_len = dhcp_len - sizeof(struct dhcp_packet);
  
  uint16_t pointer = 0;
  while(data_len > 0) {
    uint8_t dhcp_option = data[pointer];
    uint8_t dhcp_option_len = data[pointer+1];
    
    pointer +=(2 + dhcp_option_len);
    data_len -=(2 + dhcp_option_len);
    printf("cookie:%llx, option %d, len:%d\n", dhcp->cookie, dhcp_option, dhcp_option_len);
    
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

