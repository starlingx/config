class platform::ptp (
  $enabled = false,
  $mode = 'hardware',
  $transport = 'l2',
  $mechanism = 'e2e',
) {
  if $::platform::params::personality == 'controller' {
    include ::platform::network::oam::params
    $slave_interfaces   = $::platform::network::oam::params::interface_devices
    $slave_subnet       = $::platform::network::oam::params::subnet_version
    include ::platform::network::mgmt::params
    $master_interfaces  = $::platform::network::mgmt::params::interface_devices
    $master_subnet      = $::platform::network::mgmt::params::subnet_version
    if $::platform::params::system_type == 'All-in-one' {
      $slave_only = true
    } else {
      $slave_only = false
    }
  } else {
    include ::platform::network::mgmt::params
    $slave_interfaces   = $::platform::network::mgmt::params::interface_devices
    $slave_subnet       = $::platform::network::mgmt::params::subnet_version
    $slave_only = true
  }

  file { 'ptp4l_config':
    ensure  => file,
    path    => '/etc/ptp4l.conf',
    mode    => '0644',
    content => template('platform/ptp4l.conf.erb'),
  }
  -> file { 'ptp4l_service':
    ensure  => file,
    path    => '/usr/lib/systemd/system/ptp4l.service',
    mode    => '0644',
    content => template('platform/ptp4l.service.erb'),
  }
  -> file { 'ptp4l_sysconfig':
    ensure  => file,
    path    => '/etc/sysconfig/ptp4l',
    mode    => '0644',
    content => template('platform/ptp4l.erb'),
  }
  -> file { 'phc2sys_service':
    ensure  => file,
    path    => '/usr/lib/systemd/system/phc2sys.service',
    mode    => '0644',
    content => template('platform/phc2sys.service.erb'),
  }
  -> file { 'phc2sys_sysconfig':
    ensure  => file,
    path    => '/etc/sysconfig/phc2sys',
    mode    => '0644',
    content => template('platform/phc2sys.erb'),
  }
  -> exec { 'systemctl-daemon-reload':
    command     => '/usr/bin/systemctl daemon-reload',
  }

  if $enabled {
    exec { 'enable-ptp4l':
      command => '/usr/bin/systemctl enable ptp4l.service',
      require => Exec['systemctl-daemon-reload'],
    }
    -> exec { 'enable-phc2sys':
      command => '/usr/bin/systemctl enable phc2sys.service',
    }
    -> service { 'ptp4l':
      ensure     => 'running',
      enable     => true,
      name       => 'ptp4l',
      hasstatus  => true,
      hasrestart => true,
    }
    -> service { 'phc2sys':
      ensure     => 'running',
      enable     => true,
      name       => 'phc2sys',
      hasstatus  => true,
      hasrestart => true,
    }
  } else {
    exec { 'disable-ptp4l':
      command => '/usr/bin/systemctl disable ptp4l.service',
      require => Exec['systemctl-daemon-reload'],
    }
    -> exec { 'disable-phc2sys':
      command => '/usr/bin/systemctl disable phc2sys.service',
    }
    exec { 'stop-ptp4l':
      command => '/usr/bin/systemctl stop ptp4l.service',
    }
    -> exec { 'stop-phc2sys':
      command => '/usr/bin/systemctl stop phc2sys.service',
    }
  }
}
