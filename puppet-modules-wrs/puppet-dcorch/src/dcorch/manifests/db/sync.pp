#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

class dcorch::db::sync {

  include dcorch::params

  exec { 'dcorch-dbsync':
    command     => $::dcorch::params::db_sync_command,
    path        => '/usr/bin',
    refreshonly => true,
    require     => [File[$::dcorch::params::dcorch_conf], Class['dcorch']],
    logoutput   => 'on_failure',
  }
}
