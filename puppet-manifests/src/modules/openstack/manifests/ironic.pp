class openstack::ironic::params (
  $api_port = 6485,
  $service_enabled = false,
  $service_name = 'openstack-ironic',
  $region_name = undef,
  $default_endpoint_type = 'internalURL',
  $tftp_server = undef,
  $provisioning_network = undef,
  $controller_0_if = undef,
  $controller_1_if = undef,
  $netmask = undef,
) {
  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address

  include ::platform::params
  $sw_version = $::platform::params::software_version
  $ironic_basedir = '/opt/cgcs/ironic'
  $ironic_versioned_dir = "${ironic_basedir}/${sw_version}"
  $ironic_tftpboot_dir = "${ironic_versioned_dir}/tftpboot"
}


class openstack::ironic::firewall
  inherits ::openstack::ironic::params {

  if $service_enabled {
    platform::firewall::rule { 'ironic-api':
      service_name => 'ironic',
      ports        => $api_port,
    }
  }
}

class openstack::ironic::haproxy
  inherits ::openstack::ironic::params {

  if $service_enabled {
    platform::haproxy::proxy { 'ironic-restapi':
      server_name  => 's-ironic-restapi',
      public_port  => $api_port,
      private_port => $api_port,
    }

    platform::haproxy::proxy { 'ironic-tftp-restapi':
      server_name       => 's-ironic-tftp-restapi',
      public_port       => $api_port,
      private_port      => $api_port,
      public_ip_address => $tftp_server,
      enable_https      => false,
    }
  }
}

class openstack::ironic
    inherits ::openstack::ironic::params {

    include ::platform::params
    include ::platform::amqp::params
    include ::platform::network::mgmt::params
    include ::ironic::neutron
    include ::ironic::glance

    if $::platform::params::init_database {
      include ::ironic::db::postgresql
    }

    if str2bool($::is_initial_config_primary) {
      include ::ironic::db::sync
    }

    class {'::ironic':
      rabbit_use_ssl        => $::platform::amqp::params::ssl_enabled,
      default_transport_url => $::platform::amqp::params::transport_url,
      sync_db               => false,
      my_ip                 => $api_host,
    }
    if $tftp_server != undef {
      $ipa_api_url = "http://${tftp_server}:${api_port}"
    }
    else {
      $ipa_api_url = undef
    }

    # provisioning and cleaning networks are intentionally the same
    class {'::ironic::conductor':
      provisioning_network => $provisioning_network,
      cleaning_network     => $provisioning_network,
      api_url              => $ipa_api_url,
    }

    $tftp_master_path = "${ironic_tftpboot_dir}/master_images"
    class {'::ironic::drivers::pxe':
      tftp_server       => $tftp_server,
      tftp_root         => $ironic_tftpboot_dir,
      tftp_master_path  => $tftp_master_path,
      pxe_append_params => 'nofb nomodeset vga=normal console=ttyS0,115200n8',
    }

    # configure tftp root directory
    if $::platform::params::init_database {
      $ironic_tftp_root_dir = "/opt/cgcs/ironic/${sw_version}"
      file { $ironic_basedir:
        ensure => 'directory',
        owner  => 'ironic',
        group  => 'root',
        mode   => '0755',
      }
      -> file { $ironic_versioned_dir:
        ensure => 'directory',
        owner  => 'ironic',
        group  => 'root',
        mode   => '0755',
      }
      -> file { $ironic_tftpboot_dir:
        ensure => 'directory',
        owner  => 'ironic',
        group  => 'root',
        mode   => '0755',
      }
    }
    if str2bool($::is_controller_active) {
      file { "${ironic_tftpboot_dir}/pxelinux.0":
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
        source => '/usr/share/syslinux/pxelinux.0'
      }
      file { "${ironic_tftpboot_dir}/chain.c32":
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
        source => '/usr/share/syslinux/chain.c32'
      }
    }
}

class openstack::ironic::api
  inherits ::openstack::ironic::params {

  class { '::ironic::api':
    port    => $api_port,
    host_ip => $api_host,
  }

  if $service_enabled {
    include ::ironic::keystone::auth
  }

  include ::openstack::ironic::haproxy
  include ::openstack::ironic::firewall

}

class openstack::ironic::upgrade
  inherits ::openstack::ironic::params{

  file { $ironic_basedir:
    ensure => 'directory',
    owner  => 'ironic',
    group  => 'root',
    mode   => '0755',
  }
  -> file { $ironic_versioned_dir:
    ensure => 'directory',
    owner  => 'ironic',
    group  => 'root',
    mode   => '0755',
  }
  -> file { $ironic_tftpboot_dir:
    ensure => 'directory',
    owner  => 'ironic',
    group  => 'root',
    mode   => '0755',
  }
}
