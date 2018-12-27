#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Dec 2017 Creation based off puppet-sysinv
#

#
# == Parameters
#
# [use_syslog]
#   Use syslog for logging.
#   (Optional) Defaults to false.
#
# [log_facility]
#   Syslog facility to receive log lines.
#   (Optional) Defaults to LOG_USER.

class dcmanager (
  $database_connection         = '',
  $database_idle_timeout       = 3600,
  $database_max_pool_size      = 5,
  $database_max_overflow       = 10,
  $control_exchange            = 'openstack',
  $rabbit_host                 = '127.0.0.1',
  $rabbit_port                 = 5672,
  $rabbit_hosts                = false,
  $rabbit_virtual_host         = '/',
  $rabbit_userid               = 'guest',
  $rabbit_password             = false,
  $package_ensure              = 'present',
  $use_stderr                  = false,
  $log_file                    = 'dcmanager.log',
  $log_dir                     = '/var/log/dcmanager',
  $use_syslog                  = false,
  $log_facility                = 'LOG_USER',
  $verbose                     = false,
  $debug                       = false,
  $dcmanager_api_port          = 8119,
  $dcmanager_mtc_inv_label     = '/v1/',
  $region_name                 = 'RegionOne',
) {

  include dcmanager::params

  Package['dcmanager'] -> Dcmanager_config<||>

  # this anchor is used to simplify the graph between dcmanager components by
  # allowing a resource to serve as a point where the configuration of dcmanager begins
  anchor { 'dcmanager-start': }

  package { 'dcmanager':
    ensure  => $package_ensure,
    name    => $::dcmanager::params::package_name,
    require => Anchor['dcmanager-start'],
  }

  file { $::dcmanager::params::dcmanager_conf:
    ensure  => present,
    mode    => '0600',
    require => Package['dcmanager'],
  }

  dcmanager_config {
      'DEFAULT/transport_url':    value => $::platform::amqp::params::transport_url;
  }

  dcmanager_config {
    'DEFAULT/verbose':             value => $verbose;
    'DEFAULT/debug':               value => $debug;
  }

  # Automatically add psycopg2 driver to postgresql (only does this if it is missing)
  $real_connection = regsubst($database_connection,'^postgresql:','postgresql+psycopg2:')

  dcmanager_config {
    'database/connection':    value => $real_connection, secret => true;
    'database/idle_timeout':  value => $database_idle_timeout;
    'database/max_pool_size': value => $database_max_pool_size;
    'database/max_overflow':  value => $database_max_overflow;
  }

  if $use_syslog {
    dcmanager_config {
      'DEFAULT/use_syslog':           value => true;
      'DEFAULT/syslog_log_facility':  value => $log_facility;
    }
  } else {
    dcmanager_config {
      'DEFAULT/use_syslog':           value => false;
      'DEFAULT/use_stderr':           value => false;
      'DEFAULT/log_file'  :           value => $log_file;
      'DEFAULT/log_dir'   :           value => $log_dir;
    }
  }

  dcmanager_config {
    'keystone_authtoken/region_name':  value => $region_name;
  }

  file {'/etc/bash_completion.d/dcmanager.bash_completion':
    ensure  => present,
    mode    => '0644',
    content => generate('/bin/dcmanager', 'complete'),
  }

}
