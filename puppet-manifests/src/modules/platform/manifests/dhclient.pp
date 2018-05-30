class platform::dhclient::params (
  $infra_client_id = undef
) {}


class platform::dhclient
  inherits ::platform::dhclient::params {

  include ::platform::network::infra::params
  $infra_interface = $::platform::network::infra::params::interface_name
  $infra_subnet_version = $::platform::network::infra::params::subnet_version

  file { "/etc/dhcp/dhclient.conf":
    ensure => 'present',
    replace => true,
    content => template('platform/dhclient.conf.erb'),
    before => Class['::platform::network::apply'],
  }
}


class platform::dhclient::runtime {
  include ::platform::dhclient
}
