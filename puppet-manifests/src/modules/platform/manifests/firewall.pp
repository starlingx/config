define platform::firewall::rule (
  $service_name,
  $chain = 'INPUT',
  $destination = undef,
  $ensure = present,
  $host = 'ALL',
  $jump  = undef,
  $outiface = undef,
  $ports = undef,
  $proto = 'tcp',
  $table = undef,
  $tosource = undef,
) {

  include ::platform::params
  include ::platform::network::oam::params

  $ip_version = $::platform::network::oam::params::subnet_version

  $provider = $ip_version ? {
    6 => 'ip6tables',
    default => 'iptables',
  }

  $source = $host ? {
    'ALL' => $ip_version ? {
      6  => '::/0',
      default => '0.0.0.0/0'
    },
    default => $host,
  }

  $heading = $chain ? {
    'OUTPUT' => 'outgoing',
    'POSTROUTING' => 'forwarding',
    default => 'incoming',
  }

  # NAT rule
  if $jump == 'SNAT' or $jump == 'MASQUERADE' {
    firewall { "500 ${service_name} ${heading} ${title}":
      ensure      => $ensure,
      table       => $table,
      proto       => $proto,
      outiface    => $outiface,
      jump        => $jump,
      tosource    => $tosource,
      destination => $destination,
      source      => $source,
      provider    => $provider,
      chain       => $chain,
    }
  }
  else {
    if $ports == undef {
      firewall { "500 ${service_name} ${heading} ${title}":
        ensure   => $ensure,
        proto    => $proto,
        action   => 'accept',
        source   => $source,
        provider => $provider,
        chain    => $chain,
      }
    }
    else {
      firewall { "500 ${service_name} ${heading} ${title}":
        ensure   => $ensure,
        proto    => $proto,
        dport    => $ports,
        action   => 'accept',
        source   => $source,
        provider => $provider,
        chain    => $chain,
      }
    }
  }
}

class platform::firewall::calico::oam::services {
  include ::platform::params
  include ::platform::network::oam::params
  include ::platform::nfv::params
  include ::platform::fm::params
  include ::platform::patching::params
  include ::platform::sysinv::params
  include ::platform::smapi::params
  include ::platform::ceph::params
  include ::openstack::barbican::params
  include ::openstack::keystone::params
  include ::openstack::horizon::params
  include ::platform::dcmanager::params
  include ::platform::dcorch::params

  $ip_version = $::platform::network::oam::params::subnet_version

  # icmp
  $t_icmp_proto = $ip_version ? {
    6 => 'ICMPv6',
    default => 'ICMP'
  }

  # udp
  $sm_port = [2222, 2223]
  $ntp_port = [123]
  $snmp_port = [161, 162]
  $ptp_port = [319, 320]

  # tcp
  $ssh_port = [22]

  if $::platform::fm::params::service_enabled {
    $fm_port = [$::platform::fm::params::api_port]
  } else {
    $fm_port = []
  }

  $nfv_vim_port = [$::platform::nfv::params::api_port]
  $patching_port = [$::platform::patching::params::public_port]
  $sysinv_port = [$::platform::sysinv::params::api_port]
  $sm_api_port = [$::platform::smapi::params::port]
  $kube_apiserver_port = [6443]

  if $::platform::ceph::params::service_enabled {
    $ceph_radosgw_port = [$::platform::ceph::params::rgw_port]
  } else {
    $ceph_radosgw_port = []
  }

  $barbican_api_port = [$::openstack::barbican::params::api_port]

  if !$::platform::params::region_config {
    $keystone_port = [$::openstack::keystone::params::api_port]
  } else {
    $keystone_port = []
  }

  if $::platform::params::distributed_cloud_role != 'subcloud'  {
    if $::openstack::horizon::params::enable_https {
      $horizon_port = [$::openstack::horizon::params::https_port]
    } else {
      $horizon_port = [$::openstack::horizon::params::http_port]
    }
  } else {
    $horizon_port = []
  }

  if $::platform::params::distributed_cloud_role == 'systemcontroller' {
    $dc_port = [$::platform::dcmanager::params::api_port,
                $::platform::dcorch::params::sysinv_api_proxy_port,
                $::platform::dcorch::params::patch_api_proxy_port,
                $::platform::dcorch::params::identity_api_proxy_port]
  } else {
    $dc_port = []
  }

  $t_ip_version = $ip_version
  $t_udp_ports = concat($sm_port, $ntp_port, $snmp_port, $ptp_port)
  $t_tcp_ports = concat($ssh_port,
                        $fm_port, $nfv_vim_port, $patching_port, $sysinv_port, $sm_api_port,
                        $kube_apiserver_port,
                        $ceph_radosgw_port, $barbican_api_port, $keystone_port, $horizon_port,
                        $dc_port)

  $file_name = '/tmp/gnp_all_oam.yaml'
  file { $file_name:
      ensure  => file,
      content => template('platform/calico_oam_if_gnp.yaml.erb'),
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
  }
  -> exec { "apply resource ${file_name}":
    path    => '/usr/bin:/usr/sbin:/bin',
    command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f ${file_name}",
    onlyif  => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf get customresourcedefinitions.apiextensions.k8s.io'
  }
}

class platform::firewall::calico::oam::endpoints {
  include ::platform::params
  include ::platform::network::oam::params

  $host = $::platform::params::hostname
  $oam_if = $::platform::network::oam::params::interface_name
  $oam_addr = $::platform::network::oam::params::interface_address

  # create/update host endpoint to represent oam interface
  $file_name_oam = "/tmp/hep_${host}_oam.yaml"
  file { $file_name_oam:
    ensure  => file,
    content => template('platform/calico_oam_if_hep.yaml.erb'),
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
  }
  -> exec { "apply resource ${file_name_oam}":
    path    => '/usr/bin:/usr/sbin:/bin',
    command => "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f ${file_name_oam}",
    onlyif  => 'kubectl --kubeconfig=/etc/kubernetes/admin.conf get customresourcedefinitions.apiextensions.k8s.io'
  }
}

class platform::firewall::calico::oam {
  contain ::platform::firewall::calico::oam::endpoints
  contain ::platform::firewall::calico::oam::services

  Class['::platform::kubernetes::master'] -> Class[$name]
  Class['::platform::firewall::calico::oam::endpoints']
  -> Class['::platform::firewall::calico::oam::services']
}

class platform::firewall::runtime {
  include ::platform::firewall::calico::oam::endpoints
  include ::platform::firewall::calico::oam::services

  Class['::platform::firewall::calico::oam::endpoints']
  -> Class['::platform::firewall::calico::oam::services']
}
