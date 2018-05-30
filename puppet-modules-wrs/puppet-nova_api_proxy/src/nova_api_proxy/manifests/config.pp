#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2015-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  - Modify for integration
#

class nova_api_proxy::config (
  $admin_password,
  $enabled                   = false,
  $ensure_package            = 'present',
  $auth_type                 = 'password',
  $auth_strategy             = 'keystone',
  $auth_host                 = '127.0.0.1',
  $auth_port                 = 5000,
  $auth_protocol             = 'http',
  $auth_uri                  = false,
  $auth_admin_prefix         = false,
  $auth_version              = false,
  $admin_tenant_name         = 'services',
  $admin_user                = 'nova',
  $osapi_proxy_listen        = '0.0.0.0',
  $osapi_compute_listen      = '0.0.0.0',
  $nfvi_compute_listen       = '127.0.0.1',
  $nfvi_compute_listen_port  = 30003,
  $use_ssl                   = false,
  $ca_file                   = false,
  $cert_file                 = false,
  $key_file                  = false,
  $identity_uri              = undef,
  $user_domain_name          = 'Default',
  $project_domain_name       = 'Default',
  $eventlet_pool_size        = 128,
) {

  # SSL Options
  if $use_ssl {
     if !$cert_file {
       fail('The cert_file parameter is required when use_ssl is set to true')
     }
     if !$key_file {
       fail('The key_file parameter is required when use_ssl is set to true')
     }
  }

  proxy_config {
  	'DEFAULT/auth_strategy': value => $auth_strategy;
  	'DEFAULT/osapi_proxy_listen': value => $osapi_proxy_listen;
  	'DEFAULT/osapi_compute_listen': value => $osapi_compute_listen;
  	'DEFAULT/nfvi_compute_listen': value => $nfvi_compute_listen;
  	'DEFAULT/nfvi_compute_listen_port': value => $nfvi_compute_listen_port;
  	'DEFAULT/pool_size': value => $eventlet_pool_size;
  }

  if $use_ssl {
    proxy_config {
      'DEFAULT/use_ssl' :          value => $use_ssl;
      'DEFAULT/ssl_cert_file' :    value => $cert_file;
      'DEFAULT/ssl_key_file' :     value => $key_file;
    }
    if $ca_file {
      proxy_config { 'DEFAULT/ssl_ca_file' :
        value => $ca_file,
      }
    } else {
      proxy_config { 'DEFAULT/ssl_ca_file' :
        ensure => absent,
      }
    }
  } else {
    proxy_config {
      'DEFAULT/ssl_cert_file' :    ensure => absent;
      'DEFAULT/ssl_key_file' :     ensure => absent;
      'DEFAULT/ssl_ca_file' :      ensure => absent;
    }
  }

  if $auth_uri {
    $auth_uri_real = $auth_uri
  } else {
    $auth_uri_real = "${auth_protocol}://${auth_host}:5000/"
  }
  proxy_config { 'keystone_authtoken/auth_uri': value => $auth_uri_real; }

  if $auth_version {
    proxy_config { 'keystone_authtoken/auth_version': value => $auth_version; }
  } else {
    proxy_config { 'keystone_authtoken/auth_version': ensure => absent; }
  }

  if $identity_uri {
    proxy_config { 'keystone_authtoken/auth_url': value => $identity_uri; }
  }

  proxy_config {
    'keystone_authtoken/auth_type':    value => $auth_type;
    'keystone_authtoken/project_name': value => $admin_tenant_name;
    'keystone_authtoken/username':     value => $admin_user;
    'keystone_authtoken/password':    value => $admin_password, secret => true;
    'keystone_authtoken/user_domain_name':      value => $user_domain_name;
    'keystone_authtoken/project_domain_name':   value => $project_domain_name;
  }

  if $auth_admin_prefix {
    validate_re($auth_admin_prefix, '^(/.+[^/])?$')
    proxy_config {
      'keystone_authtoken/auth_admin_prefix': value => $auth_admin_prefix;
    }
  } else {
    proxy_config {
      'keystone_authtoken/auth_admin_prefix': ensure => absent;
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }
}
