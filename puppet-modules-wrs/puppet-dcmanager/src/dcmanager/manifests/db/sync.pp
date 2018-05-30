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

  exec { 'dcmanager-dbsync':
    command     => $::dcmanager::params::db_sync_command,
    path        => '/usr/bin',
    refreshonly => true,
    require     => [File[$::dcmanager::params::dcmanager_conf], Class['dcmanager']],
    logoutput   => 'on_failure',
  }
}
