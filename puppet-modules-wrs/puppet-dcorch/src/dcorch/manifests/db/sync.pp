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
  include dcorch::deps

  exec { 'dcorch-dbsync':
    command     => $::dcorch::params::db_sync_command,
    path        => '/usr/bin',
    refreshonly => true,
    logoutput   => 'on_failure',
    subscribe   => [
      Anchor['dcorch::install::end'],
      Anchor['dcorch::config::end'],
      Anchor['dcorch::db::end'],
      Anchor['dcorch::dbsync::begin']
    ],
    notify      => Anchor['dcorch::dbsync::end'],
    # Only do the db sync if both controllers are running the same software
    # version. Avoids impacting mate controller during an upgrade.
    onlyif      => "test ${::controller_sw_versions_match} = true",
  }
}
