class platform::ntp (
  $servers = [],
  $ntpdate_timeout,
) {
  file {'ntpdate_override_dir':
    path => '/etc/systemd/system/ntpdate.service.d',
    ensure => directory,
    mode => '0755',
  }

  file { 'ntpdate_tis_override':
    path    => '/etc/systemd/system/ntpdate.service.d/tis_override.conf',
    ensure  => file,
    mode    => '0644',
    content => template('platform/ntp.override.erb'),
  }

  exec { 'enable-ntpdate':
    command => '/usr/bin/systemctl enable ntpdate.service',
  }

  exec { 'enable-ntpd':
    command => '/usr/bin/systemctl enable ntpd.service',
  }

  exec { 'start-ntpdate':
    command => '/usr/bin/systemctl start ntpdate.service',
    returns => [ 0, 1 ],
    onlyif  => "grep -q '^server' /etc/ntp.conf",
  }

  exec { 'ntpdate-systemd-daemon-reload':
    command => '/usr/bin/systemctl daemon-reload',
  }

  exec { 'stop-ntpdate':
    command => '/usr/bin/systemctl stop ntpdate.service',
    returns => [ 0, 1 ],
  }

  exec { 'stop-ntpd':
    command => '/usr/bin/systemctl stop ntpd.service',
    returns => [ 0, 1 ],
  }

  service { 'ntpd':
    ensure     => 'running',
    enable     => true,
    name       => 'ntpd',
    hasstatus  => true,
    hasrestart => true,
  }

  File['ntp_config'] ->
  File['ntp_config_initial'] ->
  File['ntpdate_override_dir'] ->
  File['ntpdate_tis_override'] ->
  Exec['enable-ntpdate'] ->
  Exec['enable-ntpd'] ->
  Exec['ntpdate-systemd-daemon-reload'] ->
  Exec['stop-ntpdate'] ->
  Exec['stop-ntpd'] ->
  Exec['start-ntpdate'] ->
  Service['ntpd']
}


class platform::ntp::server {

  include ::platform::ntp

  include ::platform::params
  $peer_server = $::platform::params::mate_hostname

  file { 'ntp_config':
    path    => '/etc/ntp.conf',
    ensure  => file,
    mode    => '0640',
    content => template('platform/ntp.conf.server.erb'),
  }
  file { 'ntp_config_initial':
    path    => '/etc/ntp_initial.conf',
    ensure  => file,
    mode    => '0640',
    content => template('platform/ntp_initial.conf.server.erb'),
  }
}


class platform::ntp::client {

  if $::personality != 'controller' {
    include ::platform::ntp

    file { 'ntp_config':
      path    => '/etc/ntp.conf',
      ensure  => file,
      mode    => '0644',
      content => template('platform/ntp.conf.client.erb'),
    }
    file { 'ntp_config_initial':
      path    => '/etc/ntp_initial.conf',
      ensure  => file,
      mode    => '0644',
      content => template('platform/ntp_initial.conf.client.erb'),
    }
  }
}
