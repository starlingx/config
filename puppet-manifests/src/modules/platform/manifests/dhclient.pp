class platform::dhclient::params (
) {}


class platform::dhclient
  inherits ::platform::dhclient::params {

  file { '/etc/dhcp/dhclient.conf':
    ensure  => 'present',
    replace => true,
    content => template('platform/dhclient.conf.erb'),
    before  => Class['::platform::network::apply'],
  }
}


class platform::dhclient::runtime {
  include ::platform::dhclient
}
