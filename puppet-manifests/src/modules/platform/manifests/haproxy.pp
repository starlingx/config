class platform::haproxy::params (
  $enable_https = false,
  $private_ip_address,
  $public_ip_address,

  $global_options = undef,
  $tpm_object = undef,
  $tpm_engine = '/usr/lib64/openssl/engines/libtpm2.so',
) { }


define platform::haproxy::proxy (
  $server_name,
  $private_port,
  $public_port,
  $public_ip_address = undef,
  $private_ip_address = undef,
  $server_timeout = undef,
  $client_timeout = undef,
  $x_forwarded_proto = true,
  $enable_https = undef,
  $public_api = true,
) {
  include ::platform::haproxy::params
  
  if $enable_https != undef {
    $https_enabled = $enable_https    
  } else {
    $https_enabled = $::platform::haproxy::params::enable_https
  }  

  if $x_forwarded_proto {
    if $https_enabled and $public_api {
        $ssl_option = 'ssl crt /etc/ssl/private/server-cert.pem'
        $proto = 'X-Forwarded-Proto:\ https'
        # The value of max-age matches lighttpd.conf, and should be
        # maintained for consistency
        $hsts_option = 'Strict-Transport-Security:\ max-age=63072000;\ includeSubDomains'
    } else {
      $ssl_option = ' '
      $proto = 'X-Forwarded-Proto:\ http'
      $hsts_option = undef
    }
  } else {
      $ssl_option = ' '
      $proto = undef
      $hsts_option = undef
  }

  if $public_ip_address {
    $public_ip = $public_ip_address
  } else {
    $public_ip = $::platform::haproxy::params::public_ip_address
  }

  if $private_ip_address {
    $private_ip = $private_ip_address
  } else {
    $private_ip = $::platform::haproxy::params::private_ip_address
  }

  if $client_timeout {
    $real_client_timeout = "client ${client_timeout}"
  } else {
    $real_client_timeout = undef
  }

  haproxy::frontend { $name:
    collect_exported => false,
    name => "${name}",
    bind => {
      "${public_ip}:${public_port}" => $ssl_option,
    },
    options => {
      'default_backend' => "${name}-internal",
      'reqadd' => $proto,
      'timeout' => $real_client_timeout,
      'rspadd' => $hsts_option,
    },
  }

  if $server_timeout {
    $timeout_option = "server ${server_timeout}"
  } else {
    $timeout_option = undef
  }

  haproxy::backend { $name:
    collect_exported => false,
    name => "${name}-internal",
    options => {
      'server' => "${server_name} ${private_ip}:${private_port}",
      'timeout' => $timeout_option,
    }
  }
}


class platform::haproxy::server {

  include ::platform::params
  include ::platform::haproxy::params

  # If TPM mode is enabled then we need to configure
  # the TPM object and the TPM OpenSSL engine in HAPROXY
  $tpm_object = $::platform::haproxy::params::tpm_object
  $tpm_engine = $::platform::haproxy::params::tpm_engine
  if $tpm_object != undef {
    $tpm_options = {'tpm-object' => $tpm_object, 'tpm-engine' => $tpm_engine} 
    $global_options = merge($::platform::haproxy::params::global_options, $tpm_options)
  } else {   
    $global_options = $::platform::haproxy::params::global_options
  }

  class { '::haproxy':
      global_options => $global_options,
  }

  user { 'haproxy':
    ensure => 'present',
    shell  => '/sbin/nologin',
    groups => [$::platform::params::protected_group_name],
  } -> Class['::haproxy']
}


class platform::haproxy::reload {
  platform::sm::restart {'haproxy': }
}


class platform::haproxy::runtime {
  include ::platform::haproxy::server

  include ::platform::patching::haproxy
  include ::platform::sysinv::haproxy
  include ::platform::nfv::haproxy
  include ::platform::ceph::haproxy
  include ::platform::fm::haproxy
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::platform::dcmanager::haproxy
    include ::platform::dcorch::haproxy
  }
  include ::openstack::keystone::haproxy
  include ::openstack::neutron::haproxy
  include ::openstack::nova::haproxy
  include ::openstack::glance::haproxy
  include ::openstack::cinder::haproxy
  include ::openstack::aodh::haproxy
  include ::openstack::heat::haproxy
  include ::openstack::murano::haproxy
  include ::openstack::magnum::haproxy
  include ::openstack::ironic::haproxy
  include ::openstack::panko::haproxy
  include ::openstack::gnocchi::haproxy
  include ::openstack::swift::haproxy

  class {'::platform::haproxy::reload':
    stage => post
  }
}
