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

class sysinv::db::sync {

  include sysinv::params

  exec { 'sysinv-dbsync':
    command     => $::sysinv::params::db_sync_command,
    path        => '/usr/bin',
    user        => 'sysinv',
    refreshonly => true,
    require     => [File[$::sysinv::params::sysinv_conf], Class['sysinv']],
    logoutput   => 'on_failure',
  }
}
