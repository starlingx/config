class openstack::panko::params (
  $api_port = 8977,
  $region_name = undef,
  $service_name = 'openstack-panko',
  $service_create = false,
  $event_time_to_live = '-1',
  $service_enabled = true,
) { }

class openstack::panko
  inherits ::openstack::panko::params {

  if $service_enabled {

    include ::platform::params

    include ::panko::client
    include ::panko::keystone::authtoken

    if $::platform::params::init_database {
      include ::panko::db::postgresql
    }

    class { '::panko::db':
    }

    panko_config {
      'database/event_time_to_live':  value => $event_time_to_live;
    }

    # WRS register panko-expirer-active in cron to run once each hour
    cron { 'panko-expirer':
      ensure      => 'present',
      command     => '/usr/bin/panko-expirer-active',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute      => 10,
      hour        => '*',
      monthday    => '*',
      user        => 'root',
    }
  }
}


class openstack::panko::firewall
  inherits ::openstack::panko::params {

  platform::firewall::rule { 'panko-api':
    service_name => 'panko',
    ports        => $api_port,
  }
}

class openstack::panko::haproxy
  inherits ::openstack::panko::params {

  platform::haproxy::proxy { 'panko-restapi':
    server_name  => 's-panko-restapi',
    public_port  => $api_port,
    private_port => $api_port,
  }
}


class openstack::panko::api
  inherits ::openstack::panko::params {

  include ::platform::params

  # The panko user and service are always required and they
  # are used by subclouds when the service itself is disabled
  # on System Controller
  # whether it creates the endpoint is determined by
  # panko::keystone::auth::configure_endpoint which is
  # set via sysinv puppet
  if $::openstack::panko::params::service_create and
      $::platform::params::init_keystone {
    include ::panko::keystone::auth
  }

  if $service_enabled {

    $api_workers = $::platform::params::eng_workers_by_2

    include ::platform::network::mgmt::params
    $api_host = $::platform::network::mgmt::params::controller_address
    $url_host = $::platform::network::mgmt::params::controller_address_url

    if $::platform::params::init_database {
      include ::panko::db::postgresql
    }

    file { '/usr/share/panko/panko-api.conf':
      ensure  => file,
      content => template('openstack/panko-api.conf.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
    }
    -> class { '::panko::api':
      host    => $api_host,
      workers => $api_workers,
      sync_db => $::platform::params::init_database,
    }

    include ::openstack::panko::firewall
    include ::openstack::panko::haproxy
  }
}

class openstack::panko::runtime
  inherits ::openstack::panko::params {

  panko_config {
    'database/event_time_to_live':  value => $event_time_to_live;
  }
}
