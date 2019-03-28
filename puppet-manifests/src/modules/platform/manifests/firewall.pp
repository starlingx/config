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


define platform::firewall::common (
  $version,
  $interface,
) {

  $provider = $version ? {'ipv4' => 'iptables', 'ipv6' => 'ip6tables'}

  firewall { "000 platform accept non-oam ${version}":
    proto    => 'all',
    iniface  => "! ${$interface}",
    action   => 'accept',
    provider => $provider,
  }

  firewall { "001 platform accept related ${version}":
    proto    => 'all',
    state    => ['RELATED', 'ESTABLISHED'],
    action   => 'accept',
    provider => $provider,
  }

  # explicitly drop some types of traffic without logging
  firewall { "800 platform drop tcf-agent udp ${version}":
    proto    => 'udp',
    dport    => 1534,
    action   => 'drop',
    provider => $provider,
  }

  firewall { "800 platform drop tcf-agent tcp ${version}":
    proto    => 'tcp',
    dport    => 1534,
    action   => 'drop',
    provider => $provider,
  }

  firewall { "800 platform drop all avahi-daemon ${version}":
    proto    => 'udp',
    dport    => 5353,
    action   => 'drop',
    provider => $provider,
  }

  firewall { "999 platform log dropped ${version}":
    proto      => 'all',
    limit      => '2/min',
    jump       => 'LOG',
    log_prefix => "${provider}-in-dropped: ",
    log_level  => 4,
    provider   => $provider,
  }

  firewall { "000 platform forward non-oam ${version}":
    chain    => 'FORWARD',
    proto    => 'all',
    iniface  => "! ${interface}",
    action   => 'accept',
    provider => $provider,
  }

  firewall { "001 platform forward related ${version}":
    chain    => 'FORWARD',
    proto    => 'all',
    state    => ['RELATED', 'ESTABLISHED'],
    action   => 'accept',
    provider => $provider,
  }

  firewall { "999 platform log dropped ${version} forwarded":
    chain      => 'FORWARD',
    proto      => 'all',
    limit      => '2/min',
    jump       => 'LOG',
    log_prefix => "${provider}-fwd-dropped: ",
    log_level  => 4,
    provider   => $provider,
  }
}

# Declare OAM service rules
define platform::firewall::services (
  $version,
) {
  # platform rules to be applied before custom rules
  Firewall {
    require => undef,
  }

  $provider = $version ? {'ipv4' => 'iptables', 'ipv6' => 'ip6tables'}

  $proto_icmp = $version ? {'ipv4' => 'icmp', 'ipv6' => 'ipv6-icmp'}

  # Provider specific service rules
  firewall { "010 platform accept sm ${version}":
    proto    => 'udp',
    dport    => [2222, 2223],
    action   => 'accept',
    provider => $provider,
  }

  firewall { "011 platform accept ssh ${version}":
    proto    => 'tcp',
    dport    => 22,
    action   => 'accept',
    provider => $provider,
  }

  firewall { "200 platform accept icmp ${version}":
    proto    => $proto_icmp,
    action   => 'accept',
    provider => $provider,
  }

  firewall { "201 platform accept ntp ${version}":
    proto    => 'udp',
    dport    => 123,
    action   => 'accept',
    provider => $provider,
  }

  firewall { "202 platform accept snmp ${version}":
    proto    => 'udp',
    dport    => 161,
    action   => 'accept',
    provider => $provider,
  }

  firewall { "202 platform accept snmp trap ${version}":
    proto    => 'udp',
    dport    => 162,
    action   => 'accept',
    provider => $provider,
  }

  firewall { "203 platform accept ptp ${version}":
    proto    => 'udp',
    dport    => [319, 320],
    action   => 'accept',
    provider => $provider,
  }

  # allow IGMP Query traffic if IGMP Snooping is
  # enabled on the TOR switch
  firewall { "204 platform accept igmp ${version}":
    proto    => 'igmp',
    action   => 'accept',
    provider => $provider,
  }
}


define platform::firewall::hooks (
  $version = undef,
) {
  $protocol = $version ? {'ipv4' => 'IPv4', 'ipv6' => 'IPv6'}

  $input_pre_chain = 'INPUT-custom-pre'
  $input_post_chain = 'INPUT-custom-post'

  firewallchain { "${input_pre_chain}:filter:${protocol}":
    ensure => present,
  }
  -> firewallchain { "${input_post_chain}:filter:${protocol}":
    ensure => present,
  }
  -> firewall { "100 ${input_pre_chain} ${version}":
    proto => 'all',
    chain => 'INPUT',
    jump  => $input_pre_chain
  }
  -> firewall { "900 ${input_post_chain} ${version}":
    proto => 'all',
    chain => 'INPUT',
    jump  => $input_post_chain
  }
}


class platform::firewall::custom (
  $version = undef,
  $rules_file = undef,
) {

  $restore = $version ? {
    'ipv4' => 'iptables-restore',
    'ipv6' => 'ip6tables-restore'}

  platform::firewall::hooks { '::platform:firewall:hooks':
    version => $version,
  }

  -> exec { 'Flush firewall custom pre rules':
    command => 'iptables --flush INPUT-custom-pre',
  }
  -> exec { 'Flush firewall custom post rules':
    command => 'iptables --flush INPUT-custom-post',
  }
  -> exec { 'Apply firewall custom rules':
    command => "${restore} --noflush ${rules_file}",
  }
}


class platform::firewall::oam (
  $rules_file = undef,
) {

  include ::platform::network::oam::params
  $interface_name = $::platform::network::oam::params::interface_name
  $subnet_version = $::platform::network::oam::params::subnet_version

  $version = $subnet_version ? {
    4 => 'ipv4',
    6 => 'ipv6',
  }

  platform::firewall::common { 'platform:firewall:ipv4':
    interface => $interface_name,
    version   => 'ipv4',
  }

  -> platform::firewall::common { 'platform:firewall:ipv6':
    interface => $interface_name,
    version   => 'ipv6',
  }

  -> platform::firewall::services { 'platform:firewall:services':
    version => $version,
  }

  # Set default table policies
  -> firewallchain { 'INPUT:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
    purge  => false,
  }

  -> firewallchain { 'INPUT:filter:IPv6':
    ensure => present,
    policy => drop,
    before => undef,
    purge  => false,
  }

  -> firewallchain { 'FORWARD:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
    purge  => false,
  }

  -> firewallchain { 'FORWARD:filter:IPv6':
    ensure => present,
    policy => drop,
    before => undef,
    purge  => false,
  }

  if $rules_file {

    class { '::platform::firewall::custom':
      version    => $version,
      rules_file => $rules_file,
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
