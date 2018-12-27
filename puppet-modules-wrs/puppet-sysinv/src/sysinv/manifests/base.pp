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

class sysinv::base (
  $rabbit_password,
  $sql_connection,
  $rabbit_host            = '127.0.0.1',
  $rabbit_port            = 5672,
  $rabbit_hosts           = undef,
  $rabbit_virtual_host    = '/',
  $rabbit_userid          = 'nova',
  $package_ensure         = 'present',
  $api_paste_config       = '/etc/sysinv/api-paste.ini',
  $verbose                = false
) {

  warning('The sysinv::base class is deprecated. Use sysinv instead.')

  class { '::sysinv':
    rabbit_password     => $rabbit_password,
    sql_connection      => $sql_connection,
    rabbit_host         => $rabbit_host,
    rabbit_port         => $rabbit_port,
    rabbit_hosts        => $rabbit_hosts,
    rabbit_virtual_host => $rabbit_virtual_host,
    rabbit_userid       => $rabbit_userid,
    package_ensure      => $package_ensure,
    api_paste_config    => $api_paste_config,
    verbose             => $verbose,
  }

}
