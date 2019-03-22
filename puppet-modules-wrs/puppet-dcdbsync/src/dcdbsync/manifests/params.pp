#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

class dcdbsync::params {

  $conf_dir = '/etc/dcdbsync'
  $conf_file = '/etc/dcdbsync/dcdbsync.conf'

  if $::osfamily == 'Debian' {
    $package_name       = 'distributedcloud-dcdbsync'
    $api_package        = 'distributedcloud-dcdbsync'
    $api_service        = 'dcdbsync-api'

  } elsif($::osfamily == 'RedHat') {

    $package_name       = 'distributedcloud-dcdbsync'
    $api_package        = false
    $api_service        = 'dcdbsync-api'

  } else {
    fail("Unsupported osfamily ${::osfamily}")
  }
}
