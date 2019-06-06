#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Aug 2016: rebase mitaka
#  Jun 2016: rebase centos
#  Jun 2015: uprev kilo
#  Dec 2014: uprev juno
#  Jul 2014: rename ironic
#  Dec 2013: uprev grizzly, havana
#  Nov 2013: integrate source from https://github.com/stackforge/puppet-sysinv
#

class sysinv::agent (
  $agent_driver = false,
  $package_ensure   = 'latest',
  $enabled          = true,
  $lldp_drivers     = []
) {

  include sysinv::params

  # SM should be starting up agent
  Sysinv_config<||> ~> Service['sysinv-agent']
  Sysinv_api_paste_ini<||> ~> Service['sysinv-agent']

  if $agent_driver {
    sysinv_config {
      'DEFAULT/agent_driver': value => $agent_driver;
    }
  }

  sysinv_config {
    'lldp/drivers': value => join($lldp_drivers,',');
  }

  if $::sysinv::params::agent_package {
    Package['sysinv-agent'] -> Sysinv_config<||>
    Package['sysinv-agent'] -> Sysinv_api_paste_ini<||>
    Package['sysinv-agent'] -> Service['sysinv-agent']
    package { 'sysinv-agent':
      ensure => $package_ensure,
      name   => $::sysinv::params::agent_package,
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'sysinv-agent':
    ensure    => $ensure,
    name      => $::sysinv::params::agent_service,
    enable    => $enabled,
    hasstatus => false,
    require   => Package['sysinv'],
  }
}
