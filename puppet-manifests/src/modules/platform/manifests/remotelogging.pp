class platform::remotelogging::params (
  $enabled = false,
  $ip_address = undef,
  $port = undef,
  $transport = 'tcp',
  $service_name = 'remotelogging',
) {}


class platform::remotelogging
  inherits ::platform::remotelogging::params {

  if $enabled {
    include ::platform::params
    $system_name = $::platform::params::system_name
    $hostname = $::hostname

    if($transport == 'tls') {
      $server = "{tcp(\"${ip_address}\" port(${port}) tls(peer-verify(\"required-untrusted\")));};"
    } else {
      $server = "{${transport}(\"${ip_address}\" port(${port}));};"
    }

    $destination = 'destination remote_log_server '
    $destination_line = "${destination} ${server}"

    file_line { 'conf-add-log-server':
      path  => '/etc/syslog-ng/syslog-ng.conf',
      line  => $destination_line,
      match => $destination,
    }
    -> file_line { 'conf-add-remote':
      path  => '/etc/syslog-ng/syslog-ng.conf',
      line  => '@include "remotelogging.conf"',
      match => '#@include \"remotelogging.conf\"',
    }
    -> file { '/etc/syslog-ng/remotelogging.conf':
      ensure  => present,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('platform/remotelogging.conf.erb'),
    }
    -> exec { 'remotelogging-update-tc':
      command => "/usr/local/bin/remotelogging_tc_setup.sh ${port}"
    }
    -> Exec['syslog-ng-reload']

  } else {
    # remove remote logging configuration from syslog-ng
    file_line { 'exclude remotelogging conf':
      path  => '/etc/syslog-ng/syslog-ng.conf',
      line  => '#@include "remotelogging.conf"',
      match => '@include \"remotelogging.conf\"',
    }
    -> Exec['syslog-ng-reload']
  }

  exec { 'syslog-ng-reload':
    command => '/usr/bin/systemctl reload syslog-ng'
  }
}


class platform::remotelogging::proxy(
  $table = 'nat',
  $chain = 'POSTROUTING',
  $jump = 'MASQUERADE',
) inherits ::platform::remotelogging::params {

  include ::platform::network::oam::params

  $oam_interface = $::platform::network::oam::params::interface_name

  if $enabled {

    if $transport == 'tls' {
      $firewall_proto_transport = 'tcp'
    } else {
      $firewall_proto_transport = $transport
    }

    platform::firewall::rule { 'remotelogging-nat':
      service_name => $service_name,
      table        => $table,
      chain        => $chain,
      proto        => $firewall_proto_transport,
      outiface     => $oam_interface,
      jump         => $jump,
    }

  } else {
    platform::firewall::rule { 'remotelogging-nat':
      ensure       => absent,
      service_name => $service_name,
      table        => $table,
      chain        => $chain,
      outiface     => $oam_interface,
      jump         => $jump,
    }
  }
}


class platform::remotelogging::runtime {
  include ::platform::remotelogging

  if $::personality == 'controller' {
    include ::platform::remotelogging::proxy
  }
}
