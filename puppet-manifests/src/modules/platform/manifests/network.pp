class platform::network::pxeboot::params(
  # shared parametes with base class - required for auto hiera parameter lookup
  $interface_name = undef,
  $interface_address = undef,
  $interface_devices = [],
  $subnet_version = undef,
  $subnet_network = undef,
  $subnet_network_url = undef,
  $subnet_prefixlen = undef,
  $subnet_netmask = undef,
  $subnet_start = undef,
  $subnet_end = undef,
  $gateway_address = undef,
  $controller_address = undef,  # controller floating
  $controller_address_url = undef,  # controller floating url address
  $controller0_address = undef, # controller unit0
  $controller1_address = undef, # controller unit1
  $mtu = 1500,
) { }


class platform::network::mgmt::params(
  # shared parametes with base class - required for auto hiera parameter lookup
  $interface_name = undef,
  $interface_address = undef,
  $interface_devices = [],
  $subnet_version = undef,
  $subnet_network = undef,
  $subnet_network_url = undef,
  $subnet_prefixlen = undef,
  $subnet_netmask = undef,
  $subnet_start = undef,
  $subnet_end = undef,
  $gateway_address = undef,
  $controller_address = undef,  # controller floating
  $controller_address_url = undef,  # controller floating url address
  $controller0_address = undef, # controller unit0
  $controller1_address = undef, # controller unit1
  $mtu = 1500,
  # network type specific parameters
  $platform_nfs_address = undef,
  $cgcs_nfs_address = undef,
) { }

class platform::network::oam::params(
  # shared parametes with base class - required for auto hiera parameter lookup
  $interface_name = undef,
  $interface_address = undef,
  $interface_devices = [],
  $subnet_version = undef,
  $subnet_network = undef,
  $subnet_network_url = undef,
  $subnet_prefixlen = undef,
  $subnet_netmask = undef,
  $subnet_start = undef,
  $subnet_end = undef,
  $gateway_address = undef,
  $controller_address = undef,  # controller floating
  $controller_address_url = undef,  # controller floating url address
  $controller0_address = undef, # controller unit0
  $controller1_address = undef, # controller unit1
  $mtu = 1500,
) { }

class platform::network::cluster_host::params(
  # shared parametes with base class - required for auto hiera parameter lookup
  $interface_name = undef,
  $interface_address = undef,
  $interface_devices = [],
  $subnet_version = undef,
  $subnet_network = undef,
  $subnet_network_url = undef,
  $subnet_prefixlen = undef,
  $subnet_netmask = undef,
  $subnet_start = undef,
  $subnet_end = undef,
  $gateway_address = undef,
  $controller_address = undef,  # controller floating
  $controller_address_url = undef,  # controller floating url address
  $controller0_address = undef, # controller unit0
  $controller1_address = undef, # controller unit1
  $mtu = 1500,
) { }

define network_address (
  $address,
  $ifname,
) {
  # In AIO simplex configurations, the management addresses are assigned to the
  # loopback interface. These addresses must be assigned using the host scope
  # or assignment is prevented (can't have multiple global scope addresses on
  # the loopback interface).
  if $ifname == 'lo' {
    $options = 'scope host'
  } else {
    $options = ''
  }

  # addresses should only be configured if running in simplex, otherwise SM
  # will configure them on the active controller.
  exec { "Configuring ${name} IP address":
    command => "ip addr replace ${address} dev ${ifname} ${options}",
    onlyif  => 'test -f /etc/platform/simplex',
  }
}

class platform::addresses (
  $address_config = {},
) {
  create_resources('network_address', $address_config, {})
}

define platform::interfaces::sriov_config(
  $vf_addrs,
  $vf_driver = undef
) {
  if $vf_driver != undef {
    ensure_resource(kmod::load, $vf_driver)
    exec { "sriov-vf-bind-device: ${title}":
      command   => template('platform/sriov.bind-device.erb'),
      logoutput => true,
      require   => Kmod::Load[$vf_driver],
    }
  }
}

class platform::interfaces (
  $network_config = {},
  $route_config = {},
  $sriov_config = {}
) {
  create_resources('network_config', $network_config, {})
  create_resources('network_route', $route_config, {})
  create_resources('platform::interfaces::sriov_config', $sriov_config, {})
}

class platform::network::apply {
  include ::platform::interfaces
  include ::platform::addresses

  Network_config <| |>
  -> Exec['apply-network-config']
  -> Network_address <| |>
  -> Anchor['platform::networking']

  # Adding Network_route dependency separately, in case it's empty,
  # as puppet bug will remove dependency altogether if
  # Network_route is empty. See below.
  # https://projects.puppetlabs.com/issues/18399
  Network_config <| |>
  -> Network_route <| |>
  -> Exec['apply-network-config']

  exec {'apply-network-config':
    command => 'apply_network_config.sh',
  }
}


class platform::network (
  $mlx4_core_options = undef,
) {
  include ::platform::params
  include ::platform::network::mgmt::params
  include ::platform::network::cluster_host::params

  include ::platform::network::apply

  $management_interface = $::platform::network::mgmt::params::interface_name

  $testcmd = '/usr/local/bin/connectivity_test'

  if $::personality != 'controller' {
    if $management_interface {
      exec { 'connectivity-test-management':
        command => "${testcmd} -t 70 -i ${management_interface} controller-platform-nfs; /bin/true",
        require => Anchor['platform::networking'],
        onlyif  => 'test ! -f /etc/platform/simplex',
      }
    }
  }

  if $mlx4_core_options {
    exec { 'mlx4-core-config':
      command     => '/usr/bin/mlx4_core_config.sh',
      subscribe   => File['/etc/modprobe.d/mlx4_sriov.conf'],
      refreshonly => true
    }

    file {'/etc/modprobe.d/mlx4_sriov.conf':
      content => "options mlx4_core ${mlx4_core_options}"
    }
  }
}


class platform::network::runtime {
  include ::platform::network::apply
}
