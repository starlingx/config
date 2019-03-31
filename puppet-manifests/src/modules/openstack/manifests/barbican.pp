class openstack::barbican::params (
  $api_port = 9311,
  $region_name = undef,
  $service_name = 'barbican-api',
  $service_create = false,
  $service_enabled = true,
) { }

class openstack::barbican
  inherits ::openstack::barbican::params {

  if $service_enabled {

    include ::platform::params

    if $::platform::params::init_keystone {
      include ::barbican::keystone::auth
      include ::barbican::keystone::authtoken
    }

    if $::platform::params::init_database {
      include ::barbican::db::postgresql
    }

    barbican_config {
        'service_credentials/interface': value => 'internalURL'
    }

    file { '/var/run/barbican':
      ensure => 'directory',
      owner  => 'barbican',
      group  => 'barbican',
    }

    $api_workers = $::platform::params::eng_workers_by_4

    file_line { 'Modify workers in gunicorn-config.py':
      path  => '/etc/barbican/gunicorn-config.py',
      line  => "workers = ${api_workers}",
      match => '.*workers = .*',
      tag   => 'modify-workers',
    }
  }
}

class openstack::barbican::service
  inherits ::openstack::barbican::params {

  if $service_enabled {

    include ::platform::network::mgmt::params
    $api_host = $::platform::network::mgmt::params::subnet_version ? {
      6       => "[${::platform::network::mgmt::params::controller_address}]",
      default => $::platform::network::mgmt::params::controller_address,
    }
    $api_fqdn = $::platform::params::controller_hostname
    $url_host = "http://${api_fqdn}:${api_port}"
    if str2bool($::is_initial_config_primary) {
        $enabled = true
    } else {
        $enabled = false
    }
    include ::platform::amqp::params

    class { '::barbican::api':
      enabled                      => $enabled,
      bind_host                    => $api_host,
      bind_port                    => $api_port,
      host_href                    => $url_host,
      sync_db                      => !$::openstack::barbican::params::service_create,
      enable_proxy_headers_parsing => true,
      rabbit_use_ssl               => $::platform::amqp::params::ssl_enabled,
      default_transport_url        => $::platform::amqp::params::transport_url,
    }

    class { '::barbican::keystone::notification':
      enable_keystone_notification => true,
    }

    cron { 'barbican-cleaner':
      ensure      => 'present',
      command     => '/usr/bin/barbican-manage db clean -p -e -L /var/log/barbican/barbican-clean.log',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute      => '50',
      hour        => '*/24',
      user        => 'root',
    }
  }
}

class openstack::barbican::haproxy
  inherits ::openstack::barbican::params {

  platform::haproxy::proxy { 'barbican-restapi':
    server_name  => 's-barbican-restapi',
    public_port  => $api_port,
    private_port => $api_port,
  }
}

class openstack::barbican::api
  inherits ::openstack::barbican::params {
  include ::platform::params

  # The barbican user and service are always required and they
  # are used by subclouds when the service itself is disabled
  # on System Controller
  # whether it creates the endpoint is determined by
  # barbican::keystone::auth::configure_endpoint which is
  # set via sysinv puppet
  if ($::openstack::barbican::params::service_create and
      $::platform::params::init_keystone) {

    if ($::platform::params::distributed_cloud_role == 'subcloud' and
        $::platform::params::region_2_name != 'RegionOne') {
      Keystone_endpoint["${platform::params::region_2_name}/barbican::key-manager"] -> Keystone_endpoint['RegionOne/barbican::key-manager']
      keystone_endpoint { 'RegionOne/barbican::key-manager':
        ensure       => 'absent',
        name         => 'barbican',
        type         => 'key-manager',
        region       => 'RegionOne',
        public_url   => "http://127.0.0.1:${api_port}",
        admin_url    => "http://127.0.0.1:${api_port}",
        internal_url => "http://127.0.0.1:${api_port}"
      }
    }
  }

  if $service_enabled {
    include ::openstack::barbican::service
    include ::openstack::barbican::haproxy
  }
}

class openstack::barbican::bootstrap
  inherits ::openstack::barbican::params {

  class { '::barbican::keystone::auth':
    configure_user_role => false,
  }
  class { '::barbican::keystone::authtoken':
    auth_url => 'http://localhost:5000',
  }

  $bu_name = $::barbican::keystone::auth::auth_name
  $bu_tenant = $::barbican::keystone::auth::tenant
  keystone_role { 'creator':
    ensure => present,
  }
  keystone_user_role { "${bu_name}@${bu_tenant}":
    ensure => present,
    roles  => ['admin', 'creator'],
  }

  include ::barbican::db::postgresql

  include ::openstack::barbican
  include ::openstack::barbican::service
}

class openstack::barbican::runtime
  inherits ::openstack::barbican::params {

  include ::openstack::barbican::service
}
