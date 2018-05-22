#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Dec 2017 Creation based off puppet-sysinv
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

class dcorch (
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
  $api_paste_config            = '/etc/dcorch/api-paste.ini',
  $use_stderr                  = false,
  $log_file                    = 'dcorch.log',
  $log_dir                     = '/var/log/dcorch',
  $use_syslog                  = false,
  $log_facility                = 'LOG_USER',
  $verbose                     = false,
  $debug                       = false,
  $dcorch_api_port             = 8118,
  $dcorch_mtc_inv_label        = '/v1/',
  $region_name                 = 'RegionOne',
  $proxy_bind_host             = '0.0.0.0',
  $proxy_remote_host           = '127.0.0.1',
  $compute_bind_port           = 28774,
  $compute_remote_port         = 18774,
  $platform_bind_port          = 26385,
  $platform_remote_port        = 6385,
  $volumev2_bind_port          = 28776,
  $volumev2_remote_port        = 8776,
  $network_bind_port           = 29696,
  $network_remote_port         = 9696,
  $patching_bind_port          = 25491,
  $patching_remote_port        = 5491,
  $identity_bind_port          = 25000,
  $identity_remote_port        = 5000,
) {

  include dcorch::params

  Package['dcorch'] -> Dcorch_config<||>
  Package['dcorch'] -> Dcorch_api_paste_ini<||>

  # this anchor is used to simplify the graph between dcorch components by
  # allowing a resource to serve as a point where the configuration of dcorch begins
  anchor { 'dcorch-start': }

  package { 'dcorch':
    ensure  => $package_ensure,
    name    => $::dcorch::params::package_name,
    require => Anchor['dcorch-start'],
  }

  file { $::dcorch::params::dcorch_conf:
    ensure  => present,
    mode    => '0600',
    require => Package['dcorch'],
  }

  file { $::dcorch::params::dcorch_paste_api_ini:
    ensure  => present,
    mode    => '0600',
    require => Package['dcorch'],
  }

  dcorch_config {
      'DEFAULT/transport_url':    value => $::platform::amqp::params::transport_url;
  }

  dcorch_config {
    'DEFAULT/verbose':             value => $verbose;
    'DEFAULT/debug':               value => $debug;
    'DEFAULT/api_paste_config':    value => $api_paste_config;
  }
  
  # Automatically add psycopg2 driver to postgresql (only does this if it is missing)
  $real_connection = regsubst($database_connection,'^postgresql:','postgresql+psycopg2:')
  
  dcorch_config {
    'database/connection':    value => $real_connection, secret => true;
    'database/idle_timeout':  value => $database_idle_timeout;
    'database/max_pool_size': value => $database_max_pool_size;
    'database/max_overflow':  value => $database_max_overflow;
  }

  if $use_syslog {
    dcorch_config {
      'DEFAULT/use_syslog':           value => true;
      'DEFAULT/syslog_log_facility':  value => $log_facility;
    }
  } else {
    dcorch_config {
      'DEFAULT/use_syslog':           value => false;
      'DEFAULT/use_stderr':           value => false;
      'DEFAULT/log_file'  :           value => $log_file;
      'DEFAULT/log_dir'   :           value => $log_dir;
    }
  }

  dcorch_config {
    'keystone_authtoken/region_name':  value => $region_name;
  }
  dcorch_config {
    'compute/bind_host' : value => $proxy_bind_host;
    'compute/bind_port' : value => $compute_bind_port;
    'compute/remote_host' : value => $proxy_remote_host;
    'compute/remote_port' : value => $compute_remote_port;

    'platform/bind_host' : value => $proxy_bind_host;
    'platform/bind_port' : value => $platform_bind_port;
    'platform/remote_host' : value => $proxy_remote_host;
    'platform/remote_port' : value => $platform_remote_port;

    'volume/bind_host' : value => $proxy_bind_host;
    'volume/bind_port' : value => $volumev2_bind_port;
    'volume/remote_host' : value => $proxy_remote_host;
    'volume/remote_port' : value => $volumev2_remote_port;

    'network/bind_host' : value => $proxy_bind_host;
    'network/bind_port' : value => $network_bind_port;
    'network/remote_host' : value => $proxy_remote_host;
    'network/remote_port' : value => $network_remote_port;

    'patching/bind_host' : value => $proxy_bind_host;
    'patching/bind_port' : value => $patching_bind_port;
    'patching/remote_host' : value => '0.0.0.0';
    'patching/remote_port' : value => $patching_remote_port;

    'identity/bind_host' : value => $proxy_bind_host;
    'identity/bind_port' : value => $identity_bind_port;
    'identity/remote_host' : value => $proxy_remote_host;
    'identity/remote_port' : value => $identity_remote_port;
  }

  dcorch_api_paste_ini {
    'pipeline:dcorch-api-proxy/pipeline': value => 'filter authtoken acceptor proxyapp';
    'filter:filter/paste.filter_factory': value => 'dcorch.api.proxy.apps.filter:ApiFiller.factory';
    'filter:authtoken/paste.filter_factory': value =>  'keystonemiddleware.auth_token:filter_factory';
    'filter:acceptor/paste.filter_factory': value => 'dcorch.api.proxy.apps.acceptor:Acceptor.factory';
    'app:proxyapp/paste.app_factory': value => 'dcorch.api.proxy.apps.proxy:Proxy.factory';
  }
}
