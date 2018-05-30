#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  DEC 2017: creation (sysinv base)
#

# == Class: dcorch::keystone::auth
#
# Configures dcorch user, service and endpoint in Keystone.
#
class dcorch::keystone::auth (
  $password,
  $auth_name                     = 'dcorch',
  $email                         = 'dcorch@localhost',
  $tenant                        = 'services',
  $region                        = 'SystemController',
  $service_description           = 'DcOrchService',
  $service_name                  = 'dcorch',
  $service_type                  = 'dcorch',
  $configure_endpoint            = true,
  $configure_user                = true,
  $configure_user_role           = true,
  $public_url                    = 'http://127.0.0.1:8118/v1.0',
  $admin_url                     = 'http://127.0.0.1:8118/v1.0',
  $internal_url                  = 'http://127.0.0.1:8118/v1.0',
  $neutron_proxy_internal_url    = 'http://127.0.0.1:29696',
  $nova_proxy_internal_url       = 'http://127.0.0.1:28774/v2.1',
  $sysinv_proxy_internal_url     = 'http://127.0.0.1:26385/v1',
  $cinder_proxy_internal_url_v2  = 'http://127.0.0.1:28776/v2/%(tenant_id)s',
  $cinder_proxy_internal_url_v3  = 'http://127.0.0.1:28776/v3/%(tenant_id)s',
  $patching_proxy_internal_url   = 'http://127.0.0.1:25491',
  $neutron_proxy_public_url      = 'http://127.0.0.1:29696',
  $nova_proxy_public_url         = 'http://127.0.0.1:28774/v2.1',
  $sysinv_proxy_public_url       = 'http://127.0.0.1:26385/v1',
  $cinder_proxy_public_url_v2    = 'http://127.0.0.1:28776/v2/%(tenant_id)s',
  $cinder_proxy_public_url_v3    = 'http://127.0.0.1:28776/v3/%(tenant_id)s',
  $patching_proxy_public_url     = 'http://127.0.0.1:25491',
) {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    keystone::resource::service_identity { 'dcorch':
      configure_user      => $configure_user,
      configure_user_role => $configure_user_role,
      configure_endpoint  => false,
      service_type        => $service_type,
      service_description => $service_description,
      service_name        => $service_name,
      region              => $region,
      auth_name           => $auth_name,
      password            => $password,
      email               => $email,
      tenant              => $tenant,
      public_url          => $public_url,
      admin_url           => $admin_url,
      internal_url        => $internal_url,
    }

    keystone_endpoint { "${region}/nova::compute" :
      ensure       =>  "present",
      name         =>  "nova",
      type         =>  "compute",
      region       =>  $region,
      public_url   =>  $nova_proxy_public_url,
      admin_url    =>  $nova_proxy_internal_url,
      internal_url =>  $nova_proxy_internal_url
    }
    keystone_endpoint { "${region}/sysinv::platform" :
      ensure       =>  "present",
      name         =>  "sysinv",
      type         =>  "platform",
      region       =>  $region,
      public_url   =>  $sysinv_proxy_public_url,
      admin_url    =>  $sysinv_proxy_internal_url,
      internal_url =>  $sysinv_proxy_internal_url
    }
    keystone_endpoint { "${region}/neutron::network" :
      ensure       =>  "present",
      name         =>  "neutron",
      type         =>  "network",
      region       =>  $region,
      public_url   =>  $neutron_proxy_public_url,
      admin_url    =>  $neutron_proxy_internal_url,
      internal_url =>  $neutron_proxy_internal_url
    }

    if $::openstack::cinder::params::service_enabled {
      keystone_endpoint { "${region}/cinderv2::volumev2" :
        ensure       =>  "present",
        name         =>  "cinderv2",
        type         =>  "volumev2",
        region       =>  $region,
        public_url   =>  $cinder_proxy_public_url_v2,
        admin_url    =>  $cinder_proxy_internal_url_v2,
        internal_url =>  $cinder_proxy_internal_url_v2
      }
      keystone_endpoint { "${region}/cinderv3::volumev3" :
        ensure       =>  "present",
        name         =>  "cinderv3",
        type         =>  "volumev3",
        region       =>  $region,
        public_url   =>  $cinder_proxy_public_url_v3,
        admin_url    =>  $cinder_proxy_internal_url_v3,
        internal_url =>  $cinder_proxy_internal_url_v3
      }
    }
    keystone_endpoint { "${region}/patching::patching" :
      ensure       =>  "present",
      name         =>  "patching",
      type         =>  "patching",
      region       =>  $region,
      public_url   =>  $patching_proxy_public_url,
      admin_url    =>  $patching_proxy_internal_url,
      internal_url =>  $patching_proxy_internal_url
    }
  }
}
