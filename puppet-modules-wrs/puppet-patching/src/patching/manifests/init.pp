#
# Copyright (c) 2014-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class patching (
  $controller_multicast = '239.1.1.3',
  $agent_multicast = '239.1.1.4',
  $api_port = 5487,
  $controller_port = 5488,
  $agent_port = 5489,
) {
  include patching::params

  file { $::patching::params::patching_conf:
    ensure => present,
    owner  => 'patching',
    group  => 'patching',
    mode   => '0600',
  }

  patching_config {
    'runtime/controller_multicast':  value => $controller_multicast;
    'runtime/agent_multicast':       value => $agent_multicast;
    'runtime/api_port':              value => $api_port;
    'runtime/controller_port':       value => $controller_port;
    'runtime/agent_port':            value => $agent_port;
  }

  ~> service { 'sw-patch-agent.service':
    ensure    => 'running',
    enable    => true,
    subscribe => File[$::patching::params::patching_conf],
  }

  if $::personality == 'controller' {
    service { 'sw-patch-controller-daemon.service':
      ensure    => 'running',
      enable    => true,
      subscribe => Service['sw-patch-agent.service'],
    }
  }
}
