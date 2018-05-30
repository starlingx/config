#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv (
) {
  include nfv::params

  Package['nfv'] -> Nfv_vim_config<||>
  Package['nfv-plugins'] -> Nfv_plugin_alarm_config<||>
  Package['nfv-plugins'] -> Nfv_plugin_event_log_config<||>
  Package['nfv-plugins'] -> Nfv_plugin_nfvi_config<||>

  # This anchor is used to simplify the graph between nfv components
  # by allowing a resource to serve as a point where the configuration of
  # nfv begins
  anchor { 'nfv-start': }

  package { 'nfv':
    ensure  => 'present',
    name    => $::nfv::params::package_name,
    require => Anchor['nfv-start'],
  }

  file { $::nfv::params::nfv_vim_conf:
    ensure  => 'present',
    require => Package['nfv'],
  }

  package { 'nfv-plugins':
    ensure  => 'present',
    name    => $::nfv::params::nfv_plugin_package_name,
    require => Anchor['nfv-start'],
  }

  file { $::nfv::params::nfv_plugin_alarm_conf:
    ensure  => 'present',
    require => Package['nfv-plugins'],
  }

  file { $::nfv::params::nfv_plugin_event_log_conf:
    ensure  => 'present',
    require => Package['nfv-plugins'],
  }

  file { $::nfv::params::nfv_plugin_nfvi_conf:
    ensure  => 'present',
    require => Package['nfv-plugins'],
  }
}
