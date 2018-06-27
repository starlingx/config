class platform::etcd::params (
  $bind_address = '0.0.0.0',
  $port    = 2379,
  $node   = "controller",
)
{
  include ::platform::params

  $sw_version = $::platform::params::software_version
  $etcd_basedir = "/opt/etcd"
  $etcd_versioned_dir = "${etcd_basedir}/${sw_version}"
}

# Modify the systemd service file for etcd and 
# create an init.d script for SM to manage the service
class platform::etcd::setup {

  file {'etcd_override_dir':
    path   => '/etc/systemd/system/etcd.service.d',
    ensure => directory,
    mode   => '0755',
  } ->
  file {'etcd_override':
    path    => '/etc/systemd/system/etcd.service.d/etcd-override.conf',
    ensure  => present,
    mode    => '0644',
    source  => "puppet:///modules/${module_name}/etcd-override.conf"
  } ->
  file {'etcd_initd_script':
    path    => '/etc/init.d/etcd',
    ensure  => 'present',
    mode    => '0755',
    source  => "puppet:///modules/${module_name}/etcd"
  } ->
  exec { 'systemd-reload-daemon':
    command     => '/usr/bin/systemctl daemon-reload',
  } ->
  Service['etcd']
}

class platform::etcd::init
  inherits ::platform::etcd::params {
  
  $client_url = "http://${bind_address}:${port}"

  if str2bool($::is_initial_config_primary) {
    $service_ensure = 'running'
  }
  else {
    $service_ensure = 'stopped'
  }

  class { 'etcd':
    ensure              => 'present',
    etcd_name           => $node,
    service_enable      => false,
    service_ensure      => $service_ensure,
    cluster_enabled     => false,
    listen_client_urls  => $client_url,
    advertise_client_urls => $client_url,
    data_dir            => "${etcd_versioned_dir}/${node}.etcd",
    proxy               => "off",
  } 
}


class platform::etcd
  inherits ::platform::etcd::params {

  include ::platform::kubernetes::params

  Class['::platform::drbd::etcd'] -> Class[$name]
  
  if $::platform::kubernetes::params::enabled {
    include ::platform::etcd::datadir
    include ::platform::etcd::setup
    include ::platform::etcd::init

    Class['::platform::etcd::datadir'] ->
    Class['::platform::etcd::setup'] ->
    Class['::platform::etcd::init']

  }  
}

class platform::etcd::datadir 
  inherits ::platform::etcd::params {

  Class['::platform::drbd::etcd'] -> Class[$name]

  if $::platform::params::init_database {
    file { "${etcd_versioned_dir}":
        ensure  => 'directory',
        owner   => 'root',
        group   => 'root',
        mode    => '0755',
    }
  }
}
