class platform::vswitch {

  Class[$name] -> Class['::platform::network']

  include ::platform::vswitch::ovsdb
}


class platform::vswitch::ovsdb {
  include ::platform::params

  if $::platform::params::sdn_enabled {
    $pmon_ensure    = 'link'
    $service_ensure = 'running'
  } else {
    $pmon_ensure    = 'absent'
    $service_ensure = 'stopped'
  }

  # ensure pmon soft link
  file { "/etc/pmon.d/ovsdb-server.conf":
    ensure => $pmon_ensure,
    target => "/etc/openvswitch/ovsdb-server.pmon.conf",
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # service management (start ovsdb-server)  
  service { "openvswitch":
    ensure => $service_ensure,
    enable => $::platform::params::sdn_enabled,
  }
  
}
