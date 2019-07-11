#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

class dcmanager::db::sync {

  include dcmanager::params
  include dcmanager::deps

  exec { 'dcmanager-dbsync':
    command     => $::dcmanager::params::db_sync_command,
    path        => '/usr/bin',
    refreshonly => true,
    logoutput   => 'on_failure',
    subscribe   => [
      Anchor['dcmanager::install::end'],
      Anchor['dcmanager::config::end'],
      Anchor['dcmanager::db::end'],
      Anchor['dcmanager::dbsync::begin']
    ],
    notify      => Anchor['dcmanager::dbsync::end'],
    # Only do the db sync if both controllers are running the same software
    # version. Avoids impacting mate controller during an upgrade.
    onlyif      => "test ${::controller_sw_versions_match} = true",
  }
}
