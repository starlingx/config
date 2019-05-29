class platform::ntp (
  $ntpdate_timeout,
  $servers = [],
  $enabled = true,
) {
  if $enabled or ($::personality == 'controller'){
    $pmon_ensure = 'link'
  } else {
    $pmon_ensure = 'absent'
  }

  File['ntp_config']
  -> File['ntp_config_initial']
  -> file {'ntpdate_override_dir':
    ensure => directory,
    path   => '/etc/systemd/system/ntpdate.service.d',
    mode   => '0755',
  }
  -> file { 'ntpdate_tis_override':
    ensure  => file,
    path    => '/etc/systemd/system/ntpdate.service.d/tis_override.conf',
    mode    => '0644',
    content => template('platform/ntp.override.erb'),
  }
  -> file { 'ntp_pmon_config':
    ensure  => file,
    path    => '/etc/ntp.pmon.conf',
    mode    => '0644',
    content => template('platform/ntp.pmon.conf.erb'),
  }
  -> exec { 'systemd-daemon-reload':
    command => '/usr/bin/systemctl daemon-reload',
  }
  -> exec { 'stop-ntpdate':
    command => '/usr/bin/systemctl stop ntpdate.service',
    returns => [ 0, 1 ],
  }
  -> exec { 'stop-ntpd':
    command => '/usr/bin/systemctl stop ntpd.service',
    returns => [ 0, 1 ],
  }
  -> file { 'ntp_pmon_link':
    ensure => $pmon_ensure,
    path   => '/etc/pmon.d/ntpd.conf',
    target => '/etc/ntp.pmon.conf',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  if $enabled or ($::personality == 'controller') {
    exec { 'enable-ntpdate':
      command => '/usr/bin/systemctl enable ntpdate.service',
      require => File['ntp_pmon_link'],
    }
    -> exec { 'enable-ntpd':
      command => '/usr/bin/systemctl enable ntpd.service',
    }
    -> exec { 'start-ntpdate':
      command => '/usr/bin/systemctl start ntpdate.service',
      returns => [ 0, 1 ],
      onlyif  => "test ! -f /etc/platform/simplex || grep -q '^server' /etc/ntp.conf",
    }
    -> service { 'ntpd':
      ensure     => 'running',
      enable     => true,
      name       => 'ntpd',
      hasstatus  => true,
      hasrestart => true,
    }

    if $::personality == 'controller' {
      Class['::platform::dns']
      -> Exec['enable-ntpdate']
    } else {
      Anchor['platform::networking']
      -> Exec['enable-ntpdate']
    }
  } else {
    exec { 'disable-ntpdate':
      command => '/usr/bin/systemctl disable ntpdate.service',
      require => File['ntp_pmon_link'],
    }
    -> exec { 'disable-ntpd':
      command => '/usr/bin/systemctl disable ntpd.service',
    }
  }
}

class platform::ntp::server {

  if $::personality == 'controller' {
    include ::platform::ntp

    include ::platform::params
    $peer_server = $::platform::params::mate_hostname

    file { 'ntp_config':
      ensure  => file,
      path    => '/etc/ntp.conf',
      mode    => '0640',
      content => template('platform/ntp.conf.server.erb'),
    }
    file { 'ntp_config_initial':
      ensure  => file,
      path    => '/etc/ntp_initial.conf',
      mode    => '0640',
      content => template('platform/ntp_initial.conf.server.erb'),
    }
  }
}

class platform::ntp::client {

  if $::personality != 'controller' {
    include ::platform::ntp

    file { 'ntp_config':
      ensure  => file,
      path    => '/etc/ntp.conf',
      mode    => '0644',
      content => template('platform/ntp.conf.client.erb'),
    }
    file { 'ntp_config_initial':
      ensure  => file,
      path    => '/etc/ntp_initial.conf',
      mode    => '0644',
      content => template('platform/ntp_initial.conf.client.erb'),
    }
  }
}
