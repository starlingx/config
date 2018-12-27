class openstack::aodh::params (
  $api_port = 8042,
  $region_name = undef,
  $service_name = 'openstack-aodh',
  $service_create = false,
  $service_enabled = true,
) { }


class openstack::aodh
  inherits ::openstack::aodh::params {

  if $service_enabled {

    include ::platform::params
    include ::platform::amqp::params

    include ::aodh::auth
    include ::aodh::client
    include ::aodh::evaluator
    include ::aodh::notifier
    include ::aodh::listener
    include ::aodh::keystone::authtoken

    if $::platform::params::init_database {
      include ::aodh::db::postgresql
    }

    aodh_config {
        'service_credentials/interface': value => 'internalURL'
    }

    class { '::aodh':
      rabbit_use_ssl        => $::platform::amqp::params::ssl_enabled,
      default_transport_url => $::platform::amqp::params::transport_url,
    }

    # WRS register aodh-expirer-active in cron to run daily at the 35 minute mark
    cron { 'aodh-expirer':
      ensure      => 'present',
      command     => '/usr/bin/aodh-expirer-active',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute      => '35',
      hour        => '*/24',
      user        => 'root',
    }
  }
}


class openstack::aodh::firewall
  inherits ::openstack::aodh::params {

  platform::firewall::rule { 'aodh-api':
    service_name => 'aodh',
    ports        => $api_port,
  }
}


class openstack::aodh::haproxy
  inherits ::openstack::aodh::params {

  platform::haproxy::proxy { 'aodh-restapi':
    server_name  => 's-aodh-restapi',
    public_port  => $api_port,
    private_port => $api_port,
  }
}


class openstack::aodh::api
  inherits ::openstack::aodh::params {
  include ::platform::params

  # The aodh user and service are always required and they
  # are used by subclouds when the service itself is disabled
  # on System Controller
  # whether it creates the endpoint is determined by
  # aodh::keystone::auth::configure_endpoint which is
  # set via sysinv puppet
  if ($::openstack::aodh::params::service_create and
      $::platform::params::init_keystone) {
    include ::aodh::keystone::auth
  }

  if $service_enabled {

    include ::platform::network::mgmt::params
    $api_host = $::platform::network::mgmt::params::controller_address
    $url_host = $::platform::network::mgmt::params::controller_address_url

    file { '/usr/share/aodh/aodh-api.conf':
      ensure  => file,
      content => template('openstack/aodh-api.conf.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
    }
    -> class { '::aodh::api':
      host                         => $api_host,
      sync_db                      => $::platform::params::init_database,
      enable_proxy_headers_parsing => true,
    }

    include ::openstack::aodh::firewall
    include ::openstack::aodh::haproxy
  }
}


class openstack::aodh::runtime {
  include ::platform::amqp::params

  class { '::aodh':
    rabbit_use_ssl        => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
  }
}
