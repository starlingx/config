define platform::firewall::rule (
  $chain = 'INPUT',
  $destination = undef,
  $ensure = present,
  $host = 'ALL',
  $jump  = undef,
  $outiface = undef,
  $ports = undef,
  $proto = 'tcp',
  $service_name,
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
      chain    => $chain,
      table    => $table,
      proto    => $proto,
      outiface => $outiface,
      jump     => $jump,
      tosource => $tosource,
      destination => $destination,
      source   => $source,
      provider => $provider,
      ensure   => $ensure,
    }
  }
  else {
    if $ports == undef {
      firewall { "500 ${service_name} ${heading} ${title}":
        chain    => $chain,
        proto    => $proto,
        action   => 'accept',
        source   => $source,
        provider => $provider,
        ensure   => $ensure,
      }
    }
    else {
      firewall { "500 ${service_name} ${heading} ${title}":
        chain    => $chain,
        proto    => $proto,
        dport    => $ports,
        action   => 'accept',
        source   => $source,
        provider => $provider,
        ensure   => $ensure,
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
    proto => 'all',
    iniface => "! ${$interface}",
    action => 'accept',
    provider => $provider,
  }

  firewall { "001 platform accept related ${version}":
    proto => 'all',
    state => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
    provider => $provider,
  }

  # explicitly drop some types of traffic without logging
  firewall { "800 platform drop tcf-agent udp ${version}":
    proto => 'udp',
    dport => 1534,
    action => 'drop',
    provider => $provider,
  }

  firewall { "800 platform drop tcf-agent tcp ${version}":
    proto => 'tcp',
    dport => 1534,
    action => 'drop',
    provider => $provider,
  }

  firewall { "800 platform drop all avahi-daemon ${version}":
    proto => 'udp',
    dport => 5353,
    action => 'drop',
    provider => $provider,
  }

  firewall { "999 platform log dropped ${version}":
    proto  => 'all',
    limit => '2/min',
    jump => 'LOG',
    log_prefix => "${provider}-in-dropped: ",
    log_level => 4,
    provider => $provider,
  }

  firewall { "000 platform forward non-oam ${version}":
    chain => 'FORWARD',
    proto => 'all',
    iniface => "! ${interface}",
    action => 'accept',
    provider => $provider,
  }

  firewall { "001 platform forward related ${version}":
    chain => 'FORWARD',
    proto => 'all',
    state => ['RELATED', 'ESTABLISHED'],
    action => 'accept',
    provider => $provider,
  }

  firewall { "999 platform log dropped ${version} forwarded":
    chain => 'FORWARD',
    proto  => 'all',
    limit => '2/min',
    jump => 'LOG',
    log_prefix => "${provider}-fwd-dropped: ",
    log_level => 4,
    provider => $provider,
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
    proto => 'udp',
    dport => [2222, 2223],
    action => 'accept',
    provider => $provider,
  }

  firewall { "011 platform accept ssh ${version}":
    proto => 'tcp',
    dport => 22,
    action => 'accept',
    provider => $provider,
  }

  firewall { "200 platform accept icmp ${version}":
    proto => $proto_icmp,
    action => 'accept',
    provider => $provider,
  }

  firewall { "201 platform accept ntp ${version}":
    proto => 'udp',
    dport => 123,
    action => 'accept',
    provider => $provider,
  }

  firewall { "202 platform accept snmp ${version}":
    proto => 'udp',
    dport => 161,
    action => 'accept',
    provider => $provider,
  }

  firewall { "202 platform accept snmp trap ${version}":
    proto => 'udp',
    dport => 162,
    action => 'accept',
    provider => $provider,
  }

  firewall { "203 platform accept ptp ${version}":
    proto => 'udp',
    dport => [319, 320],
    action => 'accept',
    provider => $provider,
  }

  # allow IGMP Query traffic if IGMP Snooping is
  # enabled on the TOR switch
  firewall { "204 platform accept igmp ${version}":
    proto => 'igmp',
    action => 'accept',
    provider => $provider,
  }
}


define platform::firewall::hooks (
  $version = undef,
) {
  $protocol = $version ? {'ipv4' => 'IPv4', 'ipv6' => 'IPv6'}

  $input_pre_chain = 'INPUT-custom-pre'
  $input_post_chain = 'INPUT-custom-post'

  firewallchain { "$input_pre_chain:filter:$protocol":
    ensure => present,
  }->
  firewallchain { "$input_post_chain:filter:$protocol":
    ensure => present,
  }->
  firewall { "100 $input_pre_chain $version":
    proto => 'all',
    chain => 'INPUT',
    jump => "$input_pre_chain"
  }->
  firewall { "900 $input_post_chain $version":
    proto => 'all',
    chain => 'INPUT',
    jump => "$input_post_chain"
  }
}


class platform::firewall::custom (
  $version = undef,
  $rules_file = undef,
) {

  $restore = $version ? {
    'ipv4' => 'iptables-restore',
    'ipv6' => 'ip6tables-restore'}

  exec { 'Flush firewall custom pre rules':
    command => "iptables --flush INPUT-custom-pre",
  } ->
  exec { 'Flush firewall custom post rules':
    command => "iptables --flush INPUT-custom-post",
  } ->
  exec { 'Apply firewall custom rules':
    command => "$restore --noflush $rules_file",
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
    version => 'ipv4',
  }

  platform::firewall::common { 'platform:firewall:ipv6':
    interface => $interface_name,
    version => 'ipv6',
  }

  platform::firewall::services { 'platform:firewall:services':
    version => $version,
  }

  # Set default table policies
  firewallchain { 'INPUT:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
    purge => false,
  }

  firewallchain { 'INPUT:filter:IPv6':
    ensure => present,
    policy => drop,
    before => undef,
    purge => false,
  }

  firewallchain { 'FORWARD:filter:IPv4':
    ensure => present,
    policy => drop,
    before => undef,
    purge => false,
  }

  firewallchain { 'FORWARD:filter:IPv6':
    ensure => present,
    policy => drop,
    before => undef,
    purge => false,
  }

  if $rules_file {

    platform::firewall::hooks { '::platform:firewall:hooks':
      version => $version,
    }

    class { '::platform::firewall::custom':
      version => $version,
      rules_file => $rules_file,
    }

    # ensure custom rules are applied before system rules
    Class['::platform::firewall::custom'] -> Firewall <| |>
  }
}


class platform::firewall::runtime {
  include ::platform::firewall::oam
}
