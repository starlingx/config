#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Dec 2017 Creation based off puppet-sysinv
#

class dcmanager::manager (
  $package_ensure   = 'latest',
  $enabled          = false
) {

  include dcmanager::params
  include dcmanager::deps

  if $::dcmanager::params::manager_package {
    package { 'dcmanager-manager':
      ensure => $package_ensure,
      name   => $::dcmanager::params::manager_package,
      tag    => 'dcmanager-package',
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcmanager-manager':
    ensure    => $ensure,
    name      => $::dcmanager::params::manager_service,
    enable    => $enabled,
    hasstatus => false,
    require   => Package['dcmanager'],
    tag       => 'dcmanager-service',
  }
}
