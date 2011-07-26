#ifndef dhcp_mapping_HH
#define dhcp_mapping_HH 1

#include "config.h"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ipaddr.hh"

namespace vigil {
  using namespace std;

  enum {
    DHCP_STATE_INIT,
    DHCP_STATE_FINAL,
  };

  struct dhcp_mapping {
    struct ipaddr ip;
    struct ethernetaddr mac;
    time_t lease_end;
    uint8_t state;
    
    //------------------------------------------
    // constructor and distructors
    //------------------------------------------
    dhcp_mapping();
    //dhcp_mapping(const dhcp_mapping&);
    dhcp_mapping(const  ipaddr&, const  ethernetaddr&, uint32_t lease_end, uint8_t state);
    ~dhcp_mapping() {};

    //------------------------------------------
    // string representation
    //------------------------------------------
    std::string string();
    // -------------------------------------
    // Comparison Operators
    // ------------------------------------
    bool operator == (const dhcp_mapping&) const;
    bool operator == (const ethernetaddr&) const;
    bool operator == (const ipaddr&) const;
    //bool operator == (const ipaddr&, const ethernetaddr&) const;
  };
   
    inline
    dhcp_mapping::dhcp_mapping() { ip = ipaddr(); mac = ethernetaddr(); lease_end = 0; }
    
    inline
    dhcp_mapping::dhcp_mapping(const  ipaddr& _ip, const  ethernetaddr& _mac, uint32_t _lease_end, uint8_t _state ) {
      ip = _ip;
      mac = _mac;
      lease_end = _lease_end;
      state = _state;
    }

    std::string 
    dhcp_mapping::string() {
      //max uint32_t has 9 decimal digits
      uint16_t str_len = sizeof("255.255.255.255 FF:FF:FF:FF:FF:FF XXXXXXXXXX");
      char  buf[str_len];
 
      printf("%s %s %llu", ip.string().c_str(), mac.string().c_str(), 
	       (long long unsigned int)lease_end);
      snprintf(buf, str_len, "%s %s %llu", ip.string().c_str(), mac.string().c_str(), 
	       (long long unsigned int)lease_end);
      
      return std::string(buf);
    }

    inline bool 
    dhcp_mapping::operator == (const dhcp_mapping& dhcp) const {
      return ((dhcp.ip == this->ip) && (dhcp.mac == this->mac) );  
    }

    inline bool 
    dhcp_mapping::operator == (const ethernetaddr& mac) const {
      return (mac == this->mac);
    }

    inline bool 
    dhcp_mapping::operator == (const ipaddr& ip) const {
      return (ip == this->ip);    
    }
}


#endif // dhcp_mapping_HH
