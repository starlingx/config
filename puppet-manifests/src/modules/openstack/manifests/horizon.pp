class openstack::horizon::params (
  $secret_key,
  $openstack_host,

  $enable_https = false,
  $lockout_period = 300,
  $lockout_retries = 3,

  $horizon_ssl = false,
  $horizon_cert = undef,
  $horizon_key = undef,
  $horizon_ca = undef,

  $neutron_enable_lb = false,
  $neutron_enable_firewall = false,
  $neutron_enable_vpn = false,

  $tpm_object = undef,
  $tpm_engine = '/usr/lib64/openssl/engines/libtpm2.so',

  $http_port = 8080,
  $https_port = 8443,
) { }


class openstack::horizon
  inherits ::openstack::horizon::params {

  include ::platform::params
  include ::platform::network::mgmt::params
  include ::platform::network::pxeboot::params
  include ::openstack::keystone::params

  $controller_address       = $::platform::network::mgmt::params::controller_address
  $mgmt_subnet_network      = $::platform::network::mgmt::params::subnet_network
  $mgmt_subnet_prefixlen    = $::platform::network::mgmt::params::subnet_prefixlen
  $pxeboot_subnet_network   = $::platform::network::pxeboot::params::subnet_network
  $pxeboot_subnet_prefixlen = $::platform::network::pxeboot::params::subnet_prefixlen

  $keystone_api_version     = $::openstack::keystone::params::api_version
  $keystone_auth_uri        = $::openstack::keystone::params::auth_uri
  $keystone_host_url        = $::openstack::keystone::params::host_url

  #The intention here is to set up /www as a chroot'ed
  #environment for lighttpd so that it will remain in a jail under /www.
  #The uid and gid for www match the uid and gid in the setup package.

  group { 'www':
    ensure => 'present',
    gid    => '1877',
  }

  -> user { 'www':
    ensure => 'present',
    gid    => '1877',
    shell  => '/sbin/nologin',
    groups => ['www', 'sys_protected'],
    uid    => '1877',
  }

  file { '/www/tmp':
      ensure => directory,
      path   => '/www/tmp',
      mode   => '1700',
  }

  file {'/www/var':
      ensure  => directory,
      path    => '/www/var',
      owner   => 'www',
      require => User['www']
  }

  file {'/www/var/log':
      ensure  => directory,
      path    => '/www/var/log',
      owner   => 'www',
      require => User['www']
  }

  file {'/etc/lighttpd/lighttpd.conf':
      ensure  => present,
      content => template('openstack/lighttpd.conf.erb')
  }

  file {'/etc/lighttpd/lighttpd-inc.conf':
      ensure  => present,
      content => template('openstack/lighttpd-inc.conf.erb')
  }

  $workers = $::platform::params::eng_workers_by_2

  if str2bool($::is_initial_config) {
    exec { 'Stop lighttpd':
      command => 'systemctl stop lighttpd; systemctl disable lighttpd',
      require => User['www']
    }
  }

  if str2bool($::selinux) {
    selboolean{ 'httpd_can_network_connect':
      value      => on,
      persistent => true,
    }
  }

  # Horizon is not used in distributed cloud subclouds
  if $::platform::params::distributed_cloud_role != 'subcloud'  {

    include ::horizon::params
    file { '/etc/openstack-dashboard/horizon-config.ini':
      ensure  => present,
      content => template('openstack/horizon-params.erb'),
      mode    => '0644',
      owner   => 'root',
      group   => $::horizon::params::apache_group,
    }


    $is_django_debug = 'False'
    $bind_host = $::platform::network::mgmt::params::subnet_version ? {
      6       => '::0',
      default => '0.0.0.0',
      # TO-DO(mmagr): Add IPv6 support when hostnames are used
    }

    if $::platform::params::region_config {
      $horizon_keystone_url = "${keystone_auth_uri}/${keystone_api_version}"
      $region_2_name = $::platform::params::region_2_name
      $region_openstack_host = $openstack_host
      file { '/etc/openstack-dashboard/region-config.ini':
        ensure  => present,
        content => template('openstack/horizon-region-config.erb'),
        mode    => '0644',
      }
    } else {
      $horizon_keystone_url = "http://${$keystone_host_url}:5000/${keystone_api_version}"

      file { '/etc/openstack-dashboard/region-config.ini':
        ensure  => absent,
      }
    }

    class {'::horizon':
      secret_key            => $secret_key,
      keystone_url          => $horizon_keystone_url,
      keystone_default_role => '_member_',
      server_aliases        => [$controller_address, $::fqdn, 'localhost'],
      allowed_hosts         => '*',
      hypervisor_options    => {'can_set_mount_point' => false, },
      django_debug          => $is_django_debug,
      file_upload_temp_dir  => '/var/tmp',
      listen_ssl            => $horizon_ssl,
      horizon_cert          => $horizon_cert,
      horizon_key           => $horizon_key,
      horizon_ca            => $horizon_ca,
      neutron_options       => {
        'enable_lb'       => $neutron_enable_lb,
        'enable_firewall' => $neutron_enable_firewall,
        'enable_vpn'      => $neutron_enable_vpn
      },
      configure_apache      => false,
      compress_offline      => false,
    }

    # hack for memcached, for now we bind to localhost on ipv6
    # https://bugzilla.redhat.com/show_bug.cgi?id=1210658
    $memcached_bind_host = $::platform::network::mgmt::params::subnet_version ? {
      6       => 'localhost6',
      default => '0.0.0.0',
      # TO-DO(mmagr): Add IPv6 support when hostnames are used
    }


    # Run clearsessions daily at the 40 minute mark
    cron { 'clearsessions':
      ensure      => 'present',
      command     => '/usr/bin/horizon-clearsessions',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute      => '40',
      hour        => '*/24',
      user        => 'root',
    }

  }
}

class openstack::horizon::reload {

  # Remove all active Horizon user sessions
  # so that we don't use any stale cached data
  # such as endpoints
  exec { 'remove-Horizon-user-sessions':
    path    => ['/usr/bin'],
    command => '/usr/bin/rm -f /var/tmp/sessionid*',
  }

  platform::sm::restart {'horizon': }
  platform::sm::restart {'lighttpd': }
}


class openstack::horizon::runtime {
  include ::openstack::horizon

  class {'::openstack::horizon::reload':
    stage => post
  }
}

class openstack::lighttpd::runtime
  inherits ::openstack::horizon::params {

  Class[$name] -> Class['::platform::helm::runtime']

  file {'/etc/lighttpd/lighttpd.conf':
      ensure  => present,
      content => template('openstack/lighttpd.conf.erb')
  }
  -> platform::sm::restart {'lighttpd': }
}
