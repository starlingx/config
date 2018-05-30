class platform::dns::dnsmasq {

  # dependent template variables
  $install_uuid = $::install_uuid

  include ::platform::params
  $config_path = $::platform::params::config_path
  $pxeboot_hostname = $::platform::params::pxeboot_hostname
  $mgmt_hostname = $::platform::params::controller_hostname

  include ::platform::network::pxeboot::params
  $pxeboot_interface = $::platform::network::pxeboot::params::interface_name
  $pxeboot_subnet_version = $::platform::network::pxeboot::params::subnet_version
  $pxeboot_subnet_start = $::platform::network::pxeboot::params::subnet_start
  $pxeboot_subnet_end = $::platform::network::pxeboot::params::subnet_end
  $pxeboot_controller_address = $::platform::network::pxeboot::params::controller_address

  if $pxeboot_subnet_version == 4 {
    $pxeboot_subnet_netmask = $::platform::network::pxeboot::params::subnet_netmask
  } else {
    $pxeboot_subnet_netmask = $::platform::network::pxeboot::params::subnet_prefixlen
  }

  include ::platform::network::mgmt::params
  $mgmt_interface = $::platform::network::mgmt::params::interface_name
  $mgmt_subnet_version = $::platform::network::mgmt::params::subnet_version
  $mgmt_subnet_start = $::platform::network::mgmt::params::subnet_start
  $mgmt_subnet_end = $::platform::network::mgmt::params::subnet_end
  $mgmt_controller_address = $::platform::network::mgmt::params::controller_address
  $mgmt_network_mtu = $::platform::network::mgmt::params::mtu

  if $mgmt_subnet_version == 4 {
    $mgmt_subnet_netmask = $::platform::network::mgmt::params::subnet_netmask
  } else {
    $mgmt_subnet_netmask = $::platform::network::mgmt::params::subnet_prefixlen
  }

  include ::platform::network::infra::params
  $infra_interface = $::platform::network::infra::params::interface_name
  $infra_subnet_version = $::platform::network::infra::params::subnet_version
  $infra_subnet_start = $::platform::network::infra::params::subnet_start
  $infra_subnet_end = $::platform::network::infra::params::subnet_end
  $infra_network_mtu = $::platform::network::infra::params::mtu

  if $infra_subnet_version == 4 {
    $infra_subnet_netmask = $::platform::network::infra::params::subnet_netmask
  } else {
    $infra_subnet_netmask = $::platform::network::infra::params::subnet_prefixlen
  }

  include ::openstack::ironic::params
  $ironic_tftp_dir_version = $::platform::params::software_version
  $ironic_tftpboot_dir = $::openstack::ironic::params::ironic_tftpboot_dir
  case $::hostname {
    $::platform::params::controller_0_hostname: {
      $ironic_tftp_interface = $::openstack::ironic::params::controller_0_if
    }
    $::platform::params::controller_1_hostname: {
      $ironic_tftp_interface = $::openstack::ironic::params::controller_1_if
    }
    default: {
      $ironic_tftp_interface = undef
    }
  }

  file { "/etc/dnsmasq.conf":
      ensure => 'present',
      replace => true,
      content => template('platform/dnsmasq.conf.erb'),
  }
}


class platform::dns::resolv (
  $servers,
) {
  file { "/etc/resolv.conf":
      ensure => 'present',
      replace => true,
      content => template('platform/resolv.conf.erb')
  }
}


class platform::dns {
  include ::platform::dns::resolv
  include ::platform::dns::dnsmasq
}


class platform::dns::dnsmasq::reload {
  platform::sm::restart {'dnsmasq': }
}


class platform::dns::runtime {
  include ::platform::dns::dnsmasq

  class {'::platform::dns::dnsmasq::reload':
    stage => post
  }
}
