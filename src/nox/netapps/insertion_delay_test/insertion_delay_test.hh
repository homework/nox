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
#ifndef insertion_delay_test_HH
#define insertion_delay_test_HH

#include "component.hh"
#include "config.h"

#ifdef LOG4CXX_ENABLED
#include <boost/format.hpp>
#include "log4cxx/logger.h"
#else
#include "vlog.hh"
#endif

namespace vigil
{
  using namespace std;
  using namespace vigil::container;

  /** \brief insertion_delay_test
   * \ingroup noxcomponents
   * 
   * @author
   * @date
   */
  class insertion_delay_test
    : public Component 
  {
  public:
    /** \brief Constructor of insertion_delay_test.
     *
     * @param c context
     * @param node XML configuration (JSON object)
     */
    insertion_delay_test(const Context* c, const json_object* node)
      : Component(c)
    {}
    
    /** \brief Configure insertion_delay_test.
     * 
     * Parse the configuration, register event handlers, and
     * resolve any dependencies.
     *
     * @param c configuration
     */
    void configure(const Configuration* c);

    /** \brief Start insertion_delay_test.
     * 
     * Start the component. For example, if any threads require
     * starting, do it now.
     */
    void install();

    /** \brief Get instance of insertion_delay_test.
     * @param c context
     * @param component reference to component
     */
    static void getInstance(const container::Context* c, 
			    insertion_delay_test*& component);


  Disposition mac_pkt_handler(const Event& e);

  private:

  };
}

#endif
