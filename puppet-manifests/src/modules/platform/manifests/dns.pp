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

  include ::platform::kubernetes::params
  $service_domain = $::platform::kubernetes::params::service_domain
  $dns_service_ip = $::platform::kubernetes::params::dns_service_ip

  file { '/etc/dnsmasq.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/dnsmasq.conf.erb'),
  }
}


class platform::dns::resolv (
  $servers,
) {
  file { '/etc/resolv.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/resolv.conf.erb')
  }
}


class platform::dns {
  Anchor['platform::networking'] -> Class[$name]

  # The "contain" ensures that the resolv and dnsmasq classes are not applied
  # until the dns class is begun, which will wait for networking to be
  # complete, as per the anchor dependency above. This is necessary because
  # the networking configuration can wipe the /etc/resolv.conf file.
  contain ::platform::dns::resolv
  contain ::platform::dns::dnsmasq
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
