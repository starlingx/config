#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Dec 2017 Creation based off puppet-sysinv
#

class dcorch::snmp (
  $package_ensure   = 'latest',
  $enabled          = false,
  $bind_host        = '0.0.0.0',
  $com_str          = 'dcorchAlarmAggregator'
) {

  include dcorch::params
  include dcorch::deps

  if $::dcorch::params::snmp_package {
    package { 'dcorch-snmp':
      ensure => $package_ensure,
      name   => $::dcorch::params::snmp_package,
      tag    => 'dcorch-package',
    }
  }
  dcorch_config {
    'snmp/snmp_ip':             value => $bind_host;
    'snmp/snmp_comm_str':       value => $com_str;
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcorch-snmp':
    ensure    => $ensure,
    name      => $::dcorch::params::snmp_service,
    enable    => $enabled,
    hasstatus => false,
    tag       => 'dcorch-service',
  }

}
