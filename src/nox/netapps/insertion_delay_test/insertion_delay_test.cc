#include "insertion_delay_test.hh"

#include <boost/bind.hpp>

#include "packet-in.hh"
#include "flow.hh"
#include "component.hh"
#include "assert.hh"

namespace vigil {
  static Vlog_module lg("insertion_delay_test");
  
  void insertion_delay_test::configure(const Configuration* c) {
    lg.dbg(" Configure called ");
  }
  
  void 
  insertion_delay_test::install() {
    lg.dbg(" Install called ");
    register_handler<Packet_in_event>(boost::bind(&insertion_delay_test::mac_pkt_handler, this, _1));
  }

  Disposition
  insertion_delay_test::mac_pkt_handler(const Event& e) {
    const Packet_in_event& pi = assert_cast<const Packet_in_event&>(e);
    Flow flow(pi.in_port, *(pi.get_buffer()));
    ofp_flow_mod* ofm;
    struct ofp_action_output *ofp_act_out;
    size_t size = sizeof(*ofm) + sizeof(*ofp_act_out);

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
    ofm->buffer_id = htonl(pi.buffer_id);
    ofm->idle_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->priority = htons(OFP_DEFAULT_PRIORITY);
    ofm->flags = htons( OFPFF_SEND_FLOW_REM);

    //output packet back to the input port
    ofp_act_out = (struct ofp_action_output *) ofm->actions;
    ofp_act_out->type = htons(OFPAT_OUTPUT);
    ofp_act_out->len = htons(sizeof(struct ofp_action_output));
    ofp_act_out->port = htons(OFPP_IN_PORT); 
    ofp_act_out->max_len = htons(2000);
    send_openflow_command(pi.datapath_id, &ofm->header, false);
    return STOP;
  }

  void insertion_delay_test::getInstance(const Context* c,
					 insertion_delay_test*& component) {
    component = dynamic_cast<insertion_delay_test*>
      (c->get_by_interface(container::Interface_description
			   (typeid(insertion_delay_test).name())));
  }

  REGISTER_COMPONENT(Simple_component_factory<insertion_delay_test>,
		     insertion_delay_test);
} // vigil namespace
