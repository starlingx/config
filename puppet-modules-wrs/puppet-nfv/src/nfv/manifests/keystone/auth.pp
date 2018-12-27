#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

class nfv::keystone::auth (
  $password,
  $auth_name           = 'vim',
  $tenant              = 'services',
  $email               = 'vim@localhost',
  $region              = 'RegionOne',
  $service_description = 'Virtual Infrastructure Manager',
  $service_name        = 'vim',
  $service_type        = 'nfv',
  $configure_endpoint  = true,
  $configure_user      = true,
  $configure_user_role = true,
  $public_url          = 'http://127.0.0.1:4545',
  $admin_url           = 'http://127.0.0.1:4545',
  $internal_url        = 'http://127.0.0.1:4545',
) {

  $real_service_name = pick($service_name, $auth_name)

  keystone::resource::service_identity { $auth_name:
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
