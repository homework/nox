/* Copyright 2008 (C) Nicira, Inc.
 * Copyright 2009 (C) Stanford University.
 *
 * This file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef dhcp_HH
#define dhcp_HH

#include <vector>

#include "component.hh"
#include "netinet++/datapathid.hh"
#include "config.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

#include "dhcp_msg.hh"

namespace vigil
{
  using namespace std;
  using namespace vigil::container;

  /** \brief dhcp
   * \ingroup noxcomponents
   * 
   * @author
   * @date
   */
  class dhcp
    : public Component 
  {
  public:
    /** \brief Constructor of dhcp.
     *
     * @param c context
     * @param node XML configuration (JSON object)
     */
    dhcp(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Configure dhcp.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start dhcp.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of dhcp.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    dhcp*& component);
    
    /**
     * \brief dhcp packet handler
     *
     * A generic handler for packet_in events. This hopefully 
     * will mature latter to more specific functionality.
     */
    Disposition packet_in_handler(const Event& e);

    /**
     * \brief check when new switches join
     *
     * required in order to get a list of registered switches
     */
    Disposition datapath_join_handler(const Event& e);

    /**
     * \brief check when switches leave
     *
     * required in order to get a list of registered switches
     */
    Disposition datapath_leave_handler(const Event& e);
  private:
    size_t generate_dhcp_reply(uint8_t **buf, struct dhcp_packet  *dhcp, uint16_t dhcp_len, Flow *flow);
    void refresh_default_flows();

    std::vector<datapathid*> registered_datapath;
    //    uint16_t datapath_count;
    //uint16_t datapath_max;
    //datapathid *registered_datapath;

  };
}

#endif
