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

class sysinv::conductor (
  $conductor_driver = false,
  $package_ensure   = 'latest',
  $enabled          = true
) {

  include sysinv::params

  Sysinv_config<||> ~> Service['sysinv-conductor']

  if $conductor_driver {
    sysinv_config {
      'DEFAULT/conductor_driver': value => $conductor_driver;
    }
  }

  if $::sysinv::params::conductor_package {
    Package['sysinv-conductor'] -> Sysinv_config<||>
    Package['sysinv-conductor'] -> Sysinv_api_paste_ini<||>
    Package['sysinv-conductor'] -> Service['sysinv-conductor']
    package { 'sysinv-conductor':
      ensure => $package_ensure,
      name   => $::sysinv::params::conductor_package,
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'sysinv-conductor':
    ensure    => $ensure,
    name      => $::sysinv::params::conductor_service,
    enable    => $enabled,
    hasstatus => false,
    require   => Package['sysinv'],
  }

  Exec<| title == 'sysinv-dbsync' |> -> Service['sysinv-conductor']
}
