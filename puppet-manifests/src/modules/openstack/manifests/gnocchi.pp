class openstack::gnocchi::params (
  $api_port = 8041,
  $region_name = undef,
  $service_name = 'openstack-gnocchi',
  $service_create = false,
  $service_enabled = true,
) { }

class openstack::gnocchi
  inherits ::openstack::gnocchi::params {

  if $service_enabled {

    include ::platform::params

    include ::gnocchi
    include ::gnocchi::api
    include ::gnocchi::client
    include ::gnocchi::keystone::authtoken
    include ::gnocchi::storage::file

    if $::platform::params::init_database {
      include ::gnocchi::db::postgresql
    }

  }
}


class openstack::gnocchi::firewall
  inherits ::openstack::gnocchi::params {

  platform::firewall::rule { 'gnocchi-api':
    service_name => 'gnocchi',
    ports        => $api_port,
  }
}

class openstack::gnocchi::haproxy
  inherits ::openstack::gnocchi::params {

  platform::haproxy::proxy { 'gnocchi-restapi':
    server_name  => 's-gnocchi-restapi',
    public_port  => $api_port,
    private_port => $api_port,
  }
}

class openstack::gnocchi::metricd
  inherits ::openstack::gnocchi::params {

  if $service_enabled {

    include ::platform::params
    $metricd_workers = $::platform::params::eng_workers_by_2

    class { '::gnocchi::metricd':
      workers => $metricd_workers
    }

    if $metricd_workers > 1 {
      gnocchi_config {
        'DEFAULT/coordination_url': value => 'file:///opt/gnocchi/locks';
      }
    }

  }
}

class openstack::gnocchi::api
  inherits ::openstack::gnocchi::params {

  include ::platform::params

  # The gnocchi user and service are always required and they
  # are used by subclouds when the service itself is disabled
  # on System Controller
  # whether it creates the endpoint is determined by
  # gnocchi::keystone::auth::configure_endpoint which is
  # set via sysinv puppet
  if $::openstack::gnocchi::params::service_create and
      $::platform::params::init_keystone {
    include ::gnocchi::keystone::auth
  }

  if $service_enabled {

    $api_workers = $::platform::params::eng_workers_by_2

    include ::platform::network::mgmt::params
    $url_host = $::platform::network::mgmt::params::controller_address_url

    file { '/usr/share/gnocchi/gnocchi-api.conf':
      ensure  => file,
      content => template('openstack/gnocchi-api.conf.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
    }

    $storage_configured = inline_template("<% if File.exists?('/opt/gnocchi/tmp/gnocchi-config') -%>true<% else %>false<% end -%>")
    if ! str2bool($storage_configured) {
      include ::openstack::gnocchi::metricd
      $sacks_number = $::openstack::gnocchi::metricd::metricd_workers + 2

      if $::platform::params::init_database {
        $options = "--sacks-number ${sacks_number}"
      } else {
        $options = "--sacks-number ${sacks_number} --skip-index --skip-archive-policies-creation"
      }

      class { '::gnocchi::db::sync':
        extra_opts => $options
      }
    }

    include ::openstack::gnocchi::firewall
    include ::openstack::gnocchi::haproxy
  }
}


