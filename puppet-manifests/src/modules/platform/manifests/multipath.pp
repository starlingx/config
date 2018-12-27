class platform::multipath::params (
  $enabled = false,
) {
}

class platform::multipath
  inherits platform::multipath::params {
  if $enabled {
    file { '/etc/multipath.conf':
      ensure  => 'present',
      mode    => '0644',
      content => template('platform/multipath.conf.erb')
    }
    -> service { 'start-multipathd':
      ensure     => 'running',
      enable     => true,
      name       => 'multipathd',
      hasstatus  => true,
      hasrestart => true,
    }
    -> exec { 'systemctl-enable-multipathd':
      command => '/usr/bin/systemctl enable multipathd.service',
    }
  } else {
    service { 'stop-multipathd':
      ensure     => 'stopped',
      enable     => false,
      name       => 'multipathd',
      hasstatus  => true,
      hasrestart => true,
    }
    -> exec { 'systemctl-disable-multipathd':
      command => '/usr/bin/systemctl disable multipathd.service',
    }
    -> file { '/etc/multipath.conf':
      ensure  => 'absent',
    }
  }
}
