class openstack::heat::params (
  $api_port = 8004,
  $cfn_port = 8000,
  $cloudwatch_port = 8003,
  $region_name = undef,
  $domain_name = undef,
  $domain_admin = undef,
  $domain_pwd = undef,
  $service_name = 'openstack-heat',
  $service_tenant = undef,
  $default_endpoint_type = "internalURL",
  $service_create = false,
  $service_enabled = true,
) {
  include ::platform::params
  $api_workers =  $::platform::params::eng_workers

  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address
}


class openstack::heat
  inherits ::openstack::heat::params {

  include ::platform::params

  if $service_enabled {
    include ::platform::amqp::params

    if $::platform::params::init_database {
      include ::heat::db::postgresql
    }
    include ::heat::keystone::authtoken

    class { '::heat':
      rabbit_use_ssl => $::platform::amqp::params::ssl_enabled,
      default_transport_url => $::platform::amqp::params::transport_url,
      heat_clients_endpoint_type =>  $default_endpoint_type,
      sync_db => $::platform::params::init_database,
    }

    class { '::heat::engine':
      num_engine_workers => $::platform::params::eng_workers
    }
  }

  if $::platform::params::region_config {
    if $::openstack::glance::params::region_name != $::platform::params::region_2_name {
      $shared_service_glance = [$::openstack::glance::params::service_type]
    } else {
      $shared_service_glance = []
    }
    # skip the check if cinder region name has not been configured
    if ($::openstack::cinder::params::region_name != undef and
        $::openstack::cinder::params::region_name != $::platform::params::region_2_name) {
      $shared_service_cinder = [$::openstack::cinder::params::service_type, $::openstack::cinder::params::service_type_v2, $::openstack::cinder::params::service_type_v3]
    } else {
      $shared_service_cinder = []
    }
    $shared_services = concat($shared_service_glance, $shared_service_cinder)
    heat_config {
      'DEFAULT/region_name_for_shared_services':  value => $::platform::params::region_1_name;
      'DEFAULT/shared_services_types': value => join($shared_services,',');
    }
    # Subclouds use the region one service tenant and heat domain. In region
    # mode we duplicate these in each region.
    if $::platform::params::distributed_cloud_role != 'subcloud' {
      keystone_tenant { $service_tenant:
        ensure      => present,
        enabled     => true,
        description => "Tenant for $::platform::params::region_2_name",
      }
      class { '::heat::keystone::domain':
        domain_name   => $domain_name,
        domain_admin  => $domain_admin,
        manage_domain => true,
        manage_user   => true,
        manage_role   => true,
      }
    }
  }
  else {
    if str2bool($::is_initial_config_primary) {
      # Only setup roles and domain information on the controller during initial config
      if $service_enabled {
        keystone_user_role { 'admin@admin':
          ensure  => present,
          roles   => ['admin', '_member_', 'heat_stack_owner'],
          require => Class['::heat::engine'],
        }
      } else {
        keystone_user_role { 'admin@admin':
          ensure  => present,
          roles   => ['admin', '_member_', 'heat_stack_owner'],
        }
      }

      # Heat stack owner needs to be created
      keystone_role { 'heat_stack_owner':
        ensure => present,
      }

      class { '::heat::keystone::domain':
        manage_domain => true,
        manage_user => true,
        manage_role => true,
      }
    } else {
      # Second controller does not invoke keystone, but does need configuration
      class { '::heat::keystone::domain':
        manage_domain => false,
        manage_user => false,
        manage_role => false,
      }
    }
  }

  if $service_enabled {
    # clients_heat endpoint type is publicURL to support wait conditions
    heat_config {
      'clients_neutron/endpoint_type':   value => $default_endpoint_type;
      'clients_nova/endpoint_type':      value => $default_endpoint_type;
      'clients_glance/endpoint_type':    value => $default_endpoint_type;
      'clients_cinder/endpoint_type':    value => $default_endpoint_type;
      'clients_ceilometer/endpoint_type':value => $default_endpoint_type;
      'clients_heat/endpoint_type':      value => "publicURL";
      'clients_keystone/endpoint_type':  value => $default_endpoint_type;
    }

    # Run heat-manage purge_deleted daily at the 20 minute mark
    cron { 'heat-purge-deleted':
      ensure  => 'present',
      command => '/usr/bin/heat-purge-deleted-active',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute  => '20',
      hour    => '*/24',
      user    => 'root',
    }
  }
}



class openstack::heat::firewall
  inherits ::openstack::heat::params {

  platform::firewall::rule { 'heat-api':
    service_name => 'heat',
    ports        => $api_port,
  }

  platform::firewall::rule { 'heat-cfn':
    service_name => 'heat-cfn',
    ports        => $cfn_port,
  }

  platform::firewall::rule { 'heat-cloudwatch':
    service_name => 'heat-cloudwatch',
    ports        => $cloudwatch_port,
  }
}


class openstack::heat::haproxy
  inherits ::openstack::heat::params {

  platform::haproxy::proxy { 'heat-restapi':
    server_name => 's-heat',
    public_port => $api_port,
    private_port => $api_port,
  }

  platform::haproxy::proxy { 'heat-cfn-restapi':
    server_name => 's-heat-cfn',
    public_port => $cfn_port,
    private_port => $cfn_port,
  }

  platform::haproxy::proxy { 'heat-cloudwatch':
    server_name => 's-heat-cloudwatch',
    public_port => $cloudwatch_port,
    private_port => $cloudwatch_port,
  }
}


class openstack::heat::api
  inherits ::openstack::heat::params {

  # The heat user and service are always required and they
  # are used by subclouds when the service itself is disabled
  # on System Controller
  # whether it creates the endpoint is determined by
  # heat::keystone::auth::configure_endpoint which is
  # set via sysinv puppet
  if ($::openstack::heat::params::service_create and
      $::platform::params::init_keystone) {
    include ::heat::keystone::auth
    include ::heat::keystone::auth_cfn
  }

  if $service_enabled {
    class { '::heat::api':
      bind_host => $api_host,
      workers => $api_workers,
    }

    class { '::heat::api_cfn':
      bind_host => $api_host,
      workers => $api_workers,
    }

    class { '::heat::api_cloudwatch':
      bind_host => $api_host,
      workers => $api_workers,
    }

    include ::openstack::heat::firewall
    include ::openstack::heat::haproxy
  }
}


class openstack::heat::engine::reload {
  platform::sm::restart {'heat-engine': }
}

class openstack::heat::engine::runtime {
  include ::openstack::heat

  class {'::openstack::heat::engine::reload':
    stage => post
  }
}
