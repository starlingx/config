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

#
# class for installing qpid server for sysinv
#
#
class sysinv::qpid(
  $enabled = true,
  $user='guest',
  $password='guest',
  $file='/var/lib/qpidd/qpidd.sasldb',
  $realm='OPENSTACK'
) {

  # only configure sysinv after the queue is up
  Class['qpid::server'] -> Package<| title == 'sysinv' |>

  if ($enabled) {
    $service_ensure = 'running'

    qpid_user { $user:
      password => $password,
      file     => $file,
      realm    => $realm,
      provider => 'saslpasswd2',
      require  => Class['qpid::server'],
    }

  } else {
    $service_ensure = 'stopped'
  }

  class { '::qpid::server':
    service_ensure => $service_ensure
  }

}
