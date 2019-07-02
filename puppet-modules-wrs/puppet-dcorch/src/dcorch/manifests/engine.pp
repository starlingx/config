#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Dec 2017 Creation based off puppet-sysinv
#

class dcorch::engine (
  $package_ensure   = 'latest',
  $enabled          = false
) {

  include dcorch::params
  include dcorch::deps

  if $::dcorch::params::engine_package {
    package { 'dcorch-engine':
      ensure => $package_ensure,
      name   => $::dcorch::params::engine_package,
      tag    => 'dcorch-package',
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcorch-engine':
    ensure    => $ensure,
    name      => $::dcorch::params::engine_service,
    enable    => $enabled,
    hasstatus => false,
    tag       => 'dcorch-service',
  }

}
