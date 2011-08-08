#ifndef __HW_LEASE_HH__
#define __HW_LEASE_HH__ 1

#include "config.h"

#include "netinet++/ethernetaddr.hh"
#include "netinet++/ipaddr.hh"

namespace vigil {

    using namespace std;

    enum {
        DHCP_STATE_ADD = 0,
        DHCP_STATE_DEL,
    };

    struct Lease {

        struct ipaddr ip;
        struct ethernetaddr mc;
        std::string hn;
        unsigned long long ts; /* Last updated. */
        uint8_t st;

        Lease();
        Lease(const ipaddr&, const ethernetaddr&, char *, 
                unsigned long long, uint8_t);

        Lease(unsigned long long, char *, char *, char *, char *);

        ~Lease() {};

        std::string string();

        bool operator == (const Lease&) const;
        bool operator == (const ethernetaddr&) const;
        bool operator == (const ipaddr&) const;
    };

    inline Lease::Lease() {

        ip = ipaddr();
        mc = ethernetaddr();
        hn = std::string("NULL");
        ts = 0LL;
        st = 0;
    }

    inline Lease::Lease(const ipaddr& ip, const ethernetaddr& mac,
            char *hostname, unsigned long long timestamp, uint8_t status){

        this->ip = ip;
        this->mc = mac;
        this->hn = std::string(hostname);
        this->ts = timestamp;
        this->st = status;
    }

    inline Lease::Lease(unsigned long long ts, 
            char *st, char *mc, 
            char *ip, char *hn) {

        this->ip = ipaddr(ip);
        this->mc = ethernetaddr(mc);
        this->hn = std::string(hn);
        this->ts = ts;
        this->st = (
                (strcmp(st, "add") == 0) ? DHCP_STATE_ADD : DHCP_STATE_DEL
                );
    }

    std::string Lease::string() {

        char b[128];

        memset(b, 0, sizeof(b));
        snprintf(b, sizeof(b), "%s<=>%s [%s],%llu/%u", 

                ip.string().c_str(), 
                mc.string().c_str(), 
                hn.c_str(), ts, st);

        return std::string(b);
    }

    inline bool Lease::operator == (const Lease& lease) const {

        return ((lease.ip == this->ip) && (lease.mc == this->mc));
    }

    inline bool Lease::operator == (const ethernetaddr& mc) const {

        return (mc == this->mc);
    }

    inline bool Lease::operator == (const ipaddr& ip) const {

        return (ip == this->ip);    
    }
}

#endif /* __HW_LEASE_HH__ */

