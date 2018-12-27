class openstack::magnum::params (
  $api_port = 9511,
  $service_enabled = false,
  $service_name = 'openstack-magnum',
) {}


class openstack::magnum
  inherits ::openstack::magnum::params {

  if $::platform::params::init_database {
    include ::magnum::db::postgresql
  }

  if str2bool($::is_initial_config_primary) {
    class { '::magnum::db::sync': }
  }

  include ::platform::params
  include ::platform::amqp::params

  include ::magnum::client
  include ::magnum::clients
  include ::magnum::db
  include ::magnum::logging
  include ::magnum::conductor
  include ::magnum::certificates

  class {'::magnum':
    rabbit_use_ssl        => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
  }

  if $::platform::params::init_database {
    include ::magnum::db::postgresql
  }
}

class openstack::magnum::firewall
  inherits ::openstack::magnum::params {

  if $service_enabled {
    platform::firewall::rule { 'magnum-api':
      service_name => 'magnum',
      ports        => $api_port,
    }
  }
}


class openstack::magnum::haproxy
  inherits ::openstack::magnum::params {

  if $service_enabled {
    platform::haproxy::proxy { 'magnum-restapi':
      server_name  => 's-magnum',
      public_port  => $api_port,
      private_port => $api_port,
    }
  }
}

class openstack::magnum::api
  inherits ::openstack::magnum::params {

  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address

  if $service_enabled {
    include ::magnum::keystone::auth
    include ::magnum::keystone::authtoken
    include ::magnum::keystone::domain
  }

  class { '::magnum::api':
    enabled => false,
    host    => $api_host,
    sync_db => false,
  }

  include ::openstack::magnum::haproxy
  include ::openstack::magnum::firewall

}

