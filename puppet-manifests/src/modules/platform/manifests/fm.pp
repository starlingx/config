class platform::fm::params (
  $api_port = 18002,
  $api_host = undef,
  $region_name = undef,
  $system_name = undef,
  $service_create = false,
  $service_enabled = true,
  $trap_destinations = [],
  $sysinv_catalog_info = 'platform:sysinv:internalURL',
) { }


class platform::fm::config
  inherits ::platform::fm::params {

  $trap_dest_str = join($trap_destinations,',')
  class { '::fm':
    region_name => $region_name,
    system_name => $system_name,
    trap_destinations => $trap_dest_str,
    sysinv_catalog_info => $sysinv_catalog_info,
  }
}

class platform::fm
  inherits ::platform::fm::params {

  include ::fm::client
  include ::fm::keystone::authtoken
  include ::platform::fm::config

  include ::platform::params
  if $::platform::params::init_database {
    include ::fm::db::postgresql
  }
}

class platform::fm::firewall
  inherits ::platform::fm::params {

  platform::firewall::rule { 'fm-api':
    service_name => 'fm',
    ports        => $api_port,
  }
}

class platform::fm::haproxy
  inherits ::platform::fm::params {

  include ::platform::haproxy::params

  platform::haproxy::proxy { 'fm-api-internal':
    server_name => 's-fm-api-internal',
    public_ip_address => $::platform::haproxy::params::private_ip_address,
    public_port => $api_port,
    private_ip_address => $api_host,
    private_port => $api_port,
    public_api => false,
  }

  platform::haproxy::proxy { 'fm-api-public':
    server_name => 's-fm-api-public',
    public_port => $api_port,
    private_port => $api_port,
  }
}

class platform::fm::api
  inherits ::platform::fm::params {

  include ::platform::params

  if $service_enabled {
    if ($::platform::fm::service_create and
        $::platform::params::init_keystone) {
      include ::fm::keystone::auth
    }

    include ::platform::params

    class { '::fm::api':
      host      => $api_host,
      workers   => $::platform::params::eng_workers,
      sync_db   => $::platform::params::init_database,
    }

    include ::platform::fm::firewall
    include ::platform::fm::haproxy
  }
}

class platform::fm::runtime {

  require ::platform::fm::config

  exec { 'notify-fm-mgr':
    command => "/usr/bin/pkill -HUP fmManager",
    onlyif => "pgrep fmManager"
  }
}

