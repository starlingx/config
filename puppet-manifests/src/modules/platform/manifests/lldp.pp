class platform::lldp::params(
  $tx_interval = 30,
  $tx_hold = 4,
  $options = []
) {}


class platform::lldp
  inherits ::platform::lldp::params {
  include ::platform::params

  $hostname = $::platform::params::hostname
  $system = $::platform::params::system_name
  $version = $::platform::params::software_version

  file { '/etc/lldpd.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/lldp.conf.erb'),
      notify  => Service['lldpd'],
  }

  file { '/etc/default/lldpd':
      ensure  => 'present',
      replace => true,
      content => template('platform/lldpd.default.erb'),
      notify  => Service['lldpd'],
  }

  service { 'lldpd':
    ensure     => 'running',
    enable     => true,
    hasrestart => true,
  }
}
