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

class sysinv::db::mysql (
  $password,
  $dbname        = 'sysinv',
  $user          = 'sysinv',
  $host          = '127.0.0.1',
  $allowed_hosts = undef,
  $charset       = 'latin1',
  $cluster_id    = 'localzone'
) {

  Class['sysinv::db::mysql'] -> Exec<| title == 'sysinv-dbsync' |>
  Database[$dbname] ~> Exec<| title == 'sysinv-dbsync' |>

  mysql::db { $dbname:
    user     => $user,
    password => $password,
    host     => $host,
    charset  => $charset,
    require  => Class['mysql::config'],
  }

  # Check allowed_hosts to avoid duplicate resource declarations
  if is_array($allowed_hosts) and delete($allowed_hosts,$host) != [] {
    $real_allowed_hosts = delete($allowed_hosts,$host)
  } elsif is_string($allowed_hosts) and ($allowed_hosts != $host) {
    $real_allowed_hosts = $allowed_hosts
  }

  if $real_allowed_hosts {
    # TODO this class should be in the mysql namespace
    sysinv::db::mysql::host_access { $real_allowed_hosts:
      user     => $user,
      password => $password,
      database => $dbname,
    }
  }

}
