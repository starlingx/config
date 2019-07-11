#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# == Class: dcmanager::api
#
# Setup and configure the dcmanager API endpoint
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
#   Defaults to dcmanager
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
#   (optional) The dcmanager api port
#   Defaults to 5000
#
# [*package_ensure*]
#   (optional) The state of the package
#   Defaults to present
#
# [*bind_host*]
#   (optional) The dcmanager api bind address
#   Defaults to 0.0.0.0
#
# [*pxeboot_host*]
#   (optional) The dcmanager api pxeboot address
#   Defaults to undef
#
# [*enabled*]
#   (optional) The state of the service
#   Defaults to true
#
class dcmanager::api (
  $keystone_password,
  $keystone_admin_password,
  $keystone_admin_user        = 'admin',
  $keystone_admin_tenant      = 'admin',
  $keystone_enabled           = true,
  $keystone_tenant            = 'services',
  $keystone_user              = 'dcmanager',
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
  $enabled                    = false,
  $sync_db                    = false,
) {

  include dcmanager::params
  include dcmanager::deps

  if $::dcmanager::params::api_package {
    package { 'dcmanager':
      ensure => $package_ensure,
      name   => $::dcmanager::params::api_package,
      tag    => 'dcmanager-package',
    }
  }

  dcmanager_config {
    'DEFAULT/bind_host': value => $bind_host;
  }


  if $keystone_identity_uri {
    dcmanager_config { 'keystone_authtoken/auth_url': value => $keystone_identity_uri; }
    dcmanager_config { 'cache/auth_uri': value => "${keystone_identity_uri}/v3"; }
  } else {
    dcmanager_config { 'keystone_authtoken/auth_url': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/v3"; }
  }

  if $keystone_auth_uri {
    dcmanager_config { 'keystone_authtoken/auth_uri': value => $keystone_auth_uri; }
  } else {
    dcmanager_config {
      'keystone_authtoken/auth_uri': value => "${keystone_auth_protocol}://${keystone_auth_host}:5000/v3";
    }
  }

  if $keystone_auth_version {
    dcmanager_config { 'keystone_authtoken/auth_version': value => $keystone_auth_version; }
  } else {
    dcmanager_config { 'keystone_authtoken/auth_version': ensure => absent; }
  }

  if $keystone_enabled {
    dcmanager_config {
      'DEFAULT/auth_strategy':     value => 'keystone' ;
    }
    dcmanager_config {
      'keystone_authtoken/auth_type':    value => $auth_type;
      'keystone_authtoken/project_name': value => $keystone_tenant;
      'keystone_authtoken/username':     value => $keystone_user;
      'keystone_authtoken/password':     value => $keystone_password, secret=> true;
      'keystone_authtoken/user_domain_name':  value => $keystone_user_domain;
      'keystone_authtoken/project_domain_name':  value => $keystone_project_domain;
    }
    dcmanager_config {
      'cache/admin_tenant':       value => $keystone_admin_tenant;
      'cache/admin_username':     value => $keystone_admin_user;
      'cache/admin_password':     value => $keystone_admin_password, secret=> true;
    }

    if $keystone_auth_admin_prefix {
      validate_re($keystone_auth_admin_prefix, '^(/.+[^/])?$')
      dcmanager_config {
        'keystone_authtoken/auth_admin_prefix': value => $keystone_auth_admin_prefix;
      }
    } else {
      dcmanager_config {
        'keystone_authtoken/auth_admin_prefix': ensure => absent;
      }
    }
  }
  else
  {
    dcmanager_config {
      'DEFAULT/auth_strategy':     value => 'noauth' ;
    }
  }

  if $enabled {
    $ensure = 'running'
  } else {
    $ensure = 'stopped'
  }

  service { 'dcmanager-api':
    ensure     => $ensure,
    name       => $::dcmanager::params::api_service,
    enable     => $enabled,
    hasstatus  => true,
    hasrestart => true,
    tag        => 'dcmanager-service',
  }
  Keystone_endpoint<||> -> Service['dcmanager-api']

  if $sync_db {
    include ::dcmanager::db::sync
  }
}
