#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  
#  Nov 2017: rebase pike
#  Aug 2016: rebase mitaka
#  Jun 2016: rebase centos
#  Jun 2015: uprev kilo
#  Dec 2014: uprev juno
#  Jul 2014: rename ironic
#  Dec 2013: uprev grizzly, havana
#  Nov 2013: integrate source from https://github.com/stackforge/puppet-sysinv
#

# == Class: sysinv::api
#
# Setup and configure the sysinv API endpoint
#
# === Parameters
#
# [*keystone_password*]
#   The password to use for authentication (keystone)
#
# [*keystone_enabled*]
#   (optional) Use keystone for authentification
#   Defaults to true
#
# [*keystone_tenant*]
#   (optional) The tenant of the auth user
#   Defaults to services
#
# [*keystone_user*]
#   (optional) The name of the auth user
#   Defaults to sysinv
#
# [*keystone_auth_host*]
#   (optional) The keystone host
#   Defaults to localhost
#
# [*keystone_auth_port*]
#   (optional) The keystone auth port
#   Defaults to 5000
#
# [*keystone_auth_protocol*]
#   (optional) The protocol used to access the auth host
#   Defaults to http.
#
# [*keystone_auth_admin_prefix*]
#   (optional) The admin_prefix used to admin endpoint of the auth host
#   This allow admin auth URIs like http://auth_host:5000/keystone.
#   (where '/keystone' is the admin prefix)
#   Defaults to false for empty. If defined, should be a string with a
#   leading '/' and no trailing '/'.
#
# [*keystone_user_domain*]
#   (Optional) domain name for auth user.
#   Defaults to 'Default'.
#
# [*keystone_project_domain*]
#   (Optional) domain name for auth project.
#   Defaults to 'Default'.
#
# [*auth_type*]
#   (Optional) Authentication type to load.
#   Defaults to 'password'.
#
# [*service_port*]
#   (optional) The sysinv api port
#   Defaults to 5000
#
# [*package_ensure*]
#   (optional) The state of the package
#   Defaults to present
#
# [*bind_host*]
#   (optional) The sysinv api bind address
#   Defaults to 0.0.0.0
#
# [*pxeboot_host*]
#   (optional) The sysinv api pxeboot address
#   Defaults to undef
#
# [*enabled*]
#   (optional) The state of the service
#   Defaults to true
#
class sysinv::api (
  $keystone_password,
  $keystone_enabled           = true,
  $keystone_tenant            = 'services',
  $keystone_user              = 'sysinv',
  $keystone_auth_host         = 'localhost',
  $keystone_auth_port         = '5000',
  $keystone_auth_protocol     = 'http',
  $keystone_auth_admin_prefix = false,
  $keystone_auth_uri          = false,
  $keystone_auth_version      = false,
  $keystone_identity_uri      = false,
  $keystone_user_domain       = 'Default',
  $keystone_project_domain    = 'Default',
  $auth_type                  = 'password',
  $service_port               = '5000',
  $package_ensure             = 'latest',
  $bind_host                  = '0.0.0.0',
  $pxeboot_host               = undef,
  $enabled                    = true
) {

  include sysinv::params


  Sysinv_config<||> ~> Service['sysinv-api']
  Sysinv_config<||> ~> Exec['sysinv-dbsync']
  Sysinv_api_paste_ini<||> ~> Service['sysinv-api']

  if $::sysinv::params::api_package {
    Package['sysinv'] -> Sysinv_config<||>
    Package['sysinv'] -> Sysinv_api_paste_ini<||>
    Package['sysinv'] -> Service['sysinv-api']
    package { 'sysinv':
      ensure  => $package_ensure,
      name    => $::sysinv::params::api_package,
    }
  }

  sysinv_config {
    "DEFAULT/sysinv_api_bind_ip": value => $bind_host;
  }

  if $pxeboot_host {
    sysinv_config {
      "DEFAULT/sysinv_api_pxeboot_ip": value => $pxeboot_host;
    }
  }

  if $keystone_identity_uri {
    sysinv_config { 'keystone_authtoken/auth_url': value => $keystone_identity_uri; }
    sysinv_api_paste_ini { 'filter:authtoken/auth_url': value => $keystone_identity_uri; }
  } else {
    sysinv_config { 'keystone_authtoken/auth_url': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/"; }
    sysinv_api_paste_ini { 'filter:authtoken/auth_url': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/"; }
  }

  if $keystone_auth_uri {
    sysinv_config { 'keystone_authtoken/auth_uri': value => $keystone_auth_uri; }
    sysinv_api_paste_ini { 'filter:authtoken/auth_uri': value => $keystone_auth_uri; }
  } else {
    sysinv_config {
      'keystone_authtoken/auth_uri': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/";
    }
    sysinv_api_paste_ini {
      'filter:authtoken/auth_uri': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/";
    }
  }

  if $keystone_auth_version {
    sysinv_config { 'keystone_authtoken/auth_version': value => $keystone_auth_version; }
    sysinv_api_paste_ini { 'filter:authtoken/auth_version': value => $keystone_auth_version; }
  } else {
    sysinv_config { 'keystone_authtoken/auth_version': ensure => absent; }
    sysinv_api_paste_ini { 'filter:authtoken/auth_version': ensure => absent; }
  }

  if $keystone_enabled {
    sysinv_config {
      'DEFAULT/auth_strategy':     value => 'keystone' ;
    }
    sysinv_config {
      'keystone_authtoken/auth_type':    value => $auth_type;
      'keystone_authtoken/project_name': value => $keystone_tenant;
      'keystone_authtoken/username':     value => $keystone_user;
      'keystone_authtoken/password':     value => $keystone_password, secret=> true;
      'keystone_authtoken/user_domain_name':  value => $keystone_user_domain;
      'keystone_authtoken/project_domain_name':  value => $keystone_project_domain;
    }

    sysinv_api_paste_ini {
      'filter:authtoken/project_name': value => $keystone_tenant;
      'filter:authtoken/username':        value => $keystone_user;
      'filter:authtoken/password':    value => $keystone_password, secret => true;
      'filter:authtoken/user_domain_name': value => $keystone_user_domain;
      'filter:authtoken/project_domain_name': value => $keystone_project_domain;
    }

    if $keystone_auth_admin_prefix {
      validate_re($keystone_auth_admin_prefix, '^(/.+[^/])?$')
      sysinv_config {
        'keystone_authtoken/auth_admin_prefix': value => $keystone_auth_admin_prefix;
      }
      sysinv_api_paste_ini {
        'filter:authtoken/auth_admin_prefix': value => $keystone_auth_admin_prefix;
      }
    } else {
      sysinv_config {
        'keystone_authtoken/auth_admin_prefix': ensure => absent;
      }
      sysinv_api_paste_ini {
        'filter:authtoken/auth_admin_prefix': ensure => absent;
      }
    }
  }
  else
  {
    sysinv_config {
      'DEFAULT/auth_strategy':     value => 'noauth' ;
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'sysinv-api':
    ensure     => $ensure,
    name       => $::sysinv::params::api_service,
    enable     => $enabled,
    hasstatus  => true,
    hasrestart => true,
    tag        => 'sysinv-service',
  }
  Keystone_endpoint<||> -> Service['sysinv-api']

  exec { 'sysinv-dbsync':
    command     => $::sysinv::params::db_sync_command,
    path        => '/usr/bin',
    user        => 'sysinv',
    refreshonly => true,
    logoutput   => 'on_failure',
    require     => Package['sysinv'],
    # Only do the db sync if both controllers are running the same software
    # version. Avoids impacting mate controller during an upgrade.
    onlyif      => [
                    "test $::controller_sw_versions_match = true",
                    "systemctl status postgresql"
                   ]
  }

}
