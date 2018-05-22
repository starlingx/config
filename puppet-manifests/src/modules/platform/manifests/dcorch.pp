class platform::dcorch::params (
  $api_port = 8118,
  $region_name = undef,
  $domain_name = undef,
  $domain_admin = undef,
  $domain_pwd = undef,
  $service_name = 'dcorch',
  $default_endpoint_type = "internalURL",
  $service_create = false,
  $neutron_api_proxy_port = 29696,
  $nova_api_proxy_port = 28774,
  $sysinv_api_proxy_port = 26385,
  $cinder_api_proxy_port = 28776,
  $cinder_enable_ports   = false,
  $patch_api_proxy_port = 25491,
  $identity_api_proxy_port = 25000,
) {
  include ::platform::params

  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address
}


class platform::dcorch
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::platform::params
    include ::platform::amqp::params

    if $::platform::params::init_database {
      include ::dcorch::db::postgresql
    }

    class { '::dcorch':
      rabbit_host => $::platform::amqp::params::host_url,
      rabbit_port => $::platform::amqp::params::port,
      rabbit_userid => $::platform::amqp::params::auth_user,
      rabbit_password => $::platform::amqp::params::auth_password,
      proxy_bind_host  => $api_host,
      proxy_remote_host => $api_host,
    }
  }
}


class platform::dcorch::firewall
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::openstack::cinder::params
    platform::firewall::rule { 'dcorch-api':
      service_name => 'dcorch',
      ports        => $api_port,
    }
    platform::firewall::rule { 'dcorch-sysinv-api-proxy':
      service_name => 'dcorch-sysinv-api-proxy',
      ports => $sysinv_api_proxy_port,
    }
    platform::firewall::rule { 'dcorch-nova-api-proxy':
      service_name => 'dcorch-nova-api-proxy',
      ports => $nova_api_proxy_port,
    }
    platform::firewall::rule { 'dcorch-neutron-api-proxy':
      service_name => 'dcorch-neutron-api-proxy',
      ports => $neutron_api_proxy_port,
    }
    if $::openstack::cinder::params::service_enabled {
      platform::firewall::rule { 'dcorch-cinder-api-proxy':
        service_name => 'dcorch-cinder-api-proxy',
        ports => $cinder_api_proxy_port,
      }
    }
    platform::firewall::rule { 'dcorch-patch-api-proxy':
      service_name => 'dcorch-patch-api-proxy',
      ports => $patch_api_proxy_port,
    }
    platform::firewall::rule { 'dcorch-identity-api-proxy':
      service_name => 'dcorch-identity-api-proxy',
      ports => $identity_api_proxy_port,
    }
  }
}


class platform::dcorch::haproxy
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::openstack::cinder::params
    platform::haproxy::proxy { 'dcorch-neutron-api-proxy':
      server_name => 's-dcorch-neutron-api-proxy',
      public_port => $neutron_api_proxy_port,
      private_port => $neutron_api_proxy_port,
    }
    platform::haproxy::proxy { 'dcorch-nova-api-proxy':
      server_name => 's-dcorch-nova-api-proxy',
      public_port => $nova_api_proxy_port,
      private_port => $nova_api_proxy_port,
    }
    platform::haproxy::proxy { 'dcorch-sysinv-api-proxy':
      server_name => 's-dcorch-sysinv-api-proxy',
      public_port => $sysinv_api_proxy_port,
      private_port => $sysinv_api_proxy_port,
    }
    if $::openstack::cinder::params::service_enabled {
      platform::haproxy::proxy { 'dcorch-cinder-api-proxy':
        server_name => 's-cinder-dc-api-proxy',
        public_port => $cinder_api_proxy_port,
        private_port => $cinder_api_proxy_port,
      }
    }
    platform::haproxy::proxy { 'dcorch-patch-api-proxy':
      server_name => 's-dcorch-patch-api-proxy',
      public_port => $patch_api_proxy_port,
      private_port => $patch_api_proxy_port,
    }
    platform::haproxy::proxy { 'dcorch-identity-api-proxy':
      server_name => 's-dcorch-identity-api-proxy',
      public_port => $identity_api_proxy_port,
      private_port => $identity_api_proxy_port,
    }
  }
}

class platform::dcorch::engine 
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::dcorch::engine
  }
}

class platform::dcorch::snmp 
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    class { '::dcorch::snmp':
      bind_host => $api_host,
    }
  }
}


class platform::dcorch::api_proxy
  inherits ::platform::dcorch::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    if ($::platform::dcorch::params::service_create and
        $::platform::params::init_keystone) {
      include ::dcorch::keystone::auth
    }

    class { '::dcorch::api_proxy':
      bind_host => $api_host,
    }

    include ::platform::dcorch::firewall
    include ::platform::dcorch::haproxy
  }
}
