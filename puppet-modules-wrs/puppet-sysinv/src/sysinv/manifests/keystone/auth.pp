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

# == Class: sysinv::keystone::auth
#
# Configures Sysinv user, service and endpoint in Keystone.
#
class sysinv::keystone::auth (
  $password,
  $auth_name            = 'sysinv',
  $email                = 'sysinv@localhost',
  $tenant               = 'services',
  $region               = 'RegionOne',
  $service_description  = 'SysInvService',
  $service_name         = undef,
  $service_type         = 'platform',
  $configure_endpoint = true,
  $configure_user       = true,
  $configure_user_role  = true,
  $public_url             = 'http://127.0.0.1:6385/v1',
  $admin_url              = 'http://127.0.0.1:6385/v1',
  $internal_url           = 'http://127.0.0.1:6385/v1',
) {

  $real_service_name = pick($service_name, $auth_name)

  keystone::resource::service_identity { 'platform':
    configure_user      => $configure_user,
    configure_user_role => $configure_user_role,
    configure_endpoint  => $configure_endpoint,
    service_type        => $service_type,
    service_description => $service_description,
    service_name        => $real_service_name,
    region              => $region,
    auth_name           => $auth_name,
    password            => $password,
    email               => $email,
    tenant              => $tenant,
    public_url          => $public_url,
    admin_url           => $admin_url,
    internal_url        => $internal_url,
  }

}
