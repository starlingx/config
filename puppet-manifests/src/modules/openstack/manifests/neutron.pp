class openstack::neutron::params (
  $api_port = 9696,
  $bgp_port = 179,
  $region_name = undef,
  $service_name = 'openstack-neutron',
  $bgp_router_id = undef,
  $l3_agent_enabled = true,
  $service_create = false,
  $configure_endpoint = true
) { }

class openstack::neutron
  inherits ::openstack::neutron::params {

  include ::platform::params
  include ::platform::amqp::params

  include ::neutron::logging

  class { '::neutron':
    rabbit_use_ssl => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
    pnet_audit_enabled => $::platform::params::sdn_enabled ? { true => false, default => true },
  }
}


define openstack::neutron::sdn::controller (
  $transport,
  $ip_address,
  $port,
) {
  include ::platform::params
  include ::platform::network::oam::params
  include ::platform::network::mgmt::params

  $oam_interface = $::platform::network::oam::params::interface_name
  $mgmt_subnet_network = $::platform::network::mgmt::params::subnet_network
  $mgmt_subnet_prefixlen = $::platform::network::mgmt::params::subnet_prefixlen
  $oam_address = $::platform::network::oam::params::controller_address
  $system_type = $::platform::params::system_type

  $mgmt_subnet = "${mgmt_subnet_network}/${mgmt_subnet_prefixlen}"

  if $system_type == 'Standard' {
    if $transport == 'tls' {
      $firewall_proto_transport = 'tcp'
    } else {
      $firewall_proto_transport = $transport
    }

    platform::firewall::rule { $name:
      service_name => $name,
      table    => 'nat',
      chain    => 'POSTROUTING',
      proto    => $firewall_proto_transport,
      outiface => $oam_interface,
      tosource => $oam_address,
      destination => $ip_address,
      host     => $mgmt_subnet,
      jump     => 'SNAT',
    }
  }
}


class openstack::neutron::odl::params(
  $username = undef,
  $password= undef,
  $url = undef,
  $controller_config = {},
  $port_binding_controller = undef,
) {}

class openstack::neutron::odl
  inherits ::openstack::neutron::odl::params {

  include ::platform::params

  if $::platform::params::sdn_enabled {
    create_resources('openstack::neutron::sdn::controller', $controller_config, {})
  }
  class {'::neutron::plugins::ml2::opendaylight':
      odl_username => $username,
      odl_password => $password,
      odl_url      => $url,
      port_binding_controller => $port_binding_controller,
  }
}


class openstack::neutron::bgp
  inherits ::openstack::neutron::params {

   if $bgp_router_id {
    class {'::neutron::bgp':
        bgp_router_id => $bgp_router_id,
    }

    class {'::neutron::services::bgpvpn':
    }

    exec { 'systemctl enable neutron-bgp-dragent.service':
      command => "systemctl enable neutron-bgp-dragent.service",
    }

    exec { 'systemctl restart neutron-bgp-dragent.service':
      command => "systemctl restart neutron-bgp-dragent.service",
    }

    file { '/etc/pmon.d/':
      ensure  => directory,
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
    }

    file { "/etc/pmon.d/neutron-bgp-dragent.conf":
      ensure => link,
      target => "/etc/neutron/pmon/neutron-bgp-dragent.conf",
      owner   => 'root',
      group   => 'root',
    }
  } else {
    exec { 'pmon-stop neutron-bgp-dragent':
      command => "pmon-stop neutron-bgp-dragent",
    } ->
    exec { 'rm -f /etc/pmon.d/neutron-bgp-dragent.conf':
      command => "rm -f /etc/pmon.d/neutron-bgp-dragent.conf",
    } ->
    exec { 'systemctl disable neutron-bgp-dragent.service':
      command => "systemctl disable neutron-bgp-dragent.service",
    } ->
    exec { 'systemctl stop neutron-bgp-dragent.service':
      command => "systemctl stop neutron-bgp-dragent.service",
    }
  }
}


class openstack::neutron::sfc (
  $sfc_drivers = undef,
  $flowclassifier_drivers = undef,
  $sfc_quota_flow_classifier = undef,
  $sfc_quota_port_chain = undef,
  $sfc_quota_port_pair_group = undef,
  $sfc_quota_port_pair = undef,
) inherits ::openstack::neutron::params {

  if $sfc_drivers {
    class {'::neutron::sfc':
        sfc_drivers => $sfc_drivers,
        flowclassifier_drivers => $flowclassifier_drivers,
        quota_flow_classifier => $sfc_quota_flow_classifier,
        quota_port_chain => $sfc_quota_port_chain,
        quota_port_pair_group => $sfc_quota_port_pair_group,
        quota_port_pair => $sfc_quota_port_pair,
    }
  }
}


class openstack::neutron::server {

  include ::platform::params
  if $::platform::params::init_database {
    include ::neutron::db::postgresql
  }
  include ::neutron::plugins::ml2

  include ::neutron::server::notifications

  include ::neutron::keystone::authtoken

  class { '::neutron::server':
    api_workers => $::platform::params::eng_workers,
    rpc_workers => $::platform::params::eng_workers,
    sync_db => $::platform::params::init_database,
  }

  file { '/etc/neutron/api-paste.ini':
    ensure  => file,
    mode    => '0640',
  }

  Class['::neutron::server'] -> File['/etc/neutron/api-paste.ini']

  include ::openstack::neutron::bgp
  include ::openstack::neutron::odl
  include ::openstack::neutron::sfc
}


class openstack::neutron::agents
  inherits ::openstack::neutron::params {

  if str2bool($::disable_compute_services) {
    $pmon_ensure = absent

    class {'::neutron::agents::vswitch':
      service_ensure => stopped,
    }
    class {'::neutron::agents::l3':
      enabled => false
    }
    class {'::neutron::agents::dhcp':
      enabled => false
    }
    class {'::neutron::agents::metadata':
      enabled => false,
    }
    class {'::neutron::agents::ml2::sriov':
      enabled => false
    }
  } else {
    $pmon_ensure = link

    class {'::neutron::agents::metadata':
      metadata_workers => $::platform::params::eng_workers_by_4
    }

    class { '::neutron::agents::l3':
      enabled => $l3_agent_enabled,
    }

    include ::neutron::agents::dhcp
    include ::neutron::agents::ml2::sriov
  }

  file { "/etc/pmon.d/neutron-dhcp-agent.conf":
    ensure => $pmon_ensure,
    target => "/etc/neutron/pmon/neutron-dhcp-agent.conf",
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  }

  file { "/etc/pmon.d/neutron-metadata-agent.conf":
    ensure => $pmon_ensure,
    target => "/etc/neutron/pmon/neutron-metadata-agent.conf",
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  }

  file { "/etc/pmon.d/neutron-sriov-nic-agent.conf":
    ensure => $pmon_ensure,
    target => "/etc/neutron/pmon/neutron-sriov-nic-agent.conf",
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  }
}


class openstack::neutron::firewall
  inherits ::openstack::neutron::params {

  platform::firewall::rule { 'neutron-api':
    service_name => 'neutron',
    ports        => $api_port,
  }

   if $bgp_router_id {
      platform::firewall::rule { 'ryu-bgp-port':
        service_name => 'neutron',
        ports        => $bgp_port,
      }
   } else {
      platform::firewall::rule { 'ryu-bgp-port':
        service_name => 'neutron',
        ports        => $bgp_port,
        ensure       => absent
      }
   }

}


class openstack::neutron::haproxy
  inherits ::openstack::neutron::params {

  platform::haproxy::proxy { 'neutron-restapi':
    server_name => 's-neutron',
    public_port => $api_port,
    private_port => $api_port,
  }
}


class openstack::neutron::api
  inherits ::openstack::neutron::params {

  include ::platform::params

  if ($::openstack::neutron::params::service_create and
      $::platform::params::init_keystone) {

    include ::neutron::keystone::auth
  }

  if $::openstack::neutron::params::configure_endpoint {
    include ::openstack::neutron::firewall
    include ::openstack::neutron::haproxy
  }
}


class openstack::neutron::server::reload {
  platform::sm::restart {'neutron-server': }
}


class openstack::neutron::server::runtime {
  include ::openstack::neutron
  include ::openstack::neutron::server
  include ::openstack::neutron::firewall

  class {'::openstack::neutron::server::reload':
    stage => post
  }
}
