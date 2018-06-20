class openstack::glance::params (
  $service_enabled = true,
  $api_port = 9292,
  $api_host,
  $region_name = undef,
  $service_type = 'image',
  $glance_directory = '/opt/cgcs/glance',
  $glance_image_conversion_dir = '/opt/img-conversions/glance',
  $enabled_backends = [],
  $service_create = false,
  $configured_registry_host = '0.0.0.0',
  $remote_registry_region_name = undef,
  $glance_cached = false,
  $glance_delete_interval = 6,
  $rbd_store_pool = 'images',
  $rbd_store_ceph_conf = '/etc/ceph/ceph.conf',
) { }


class openstack::glance
  inherits ::openstack::glance::params {

  if $service_enabled {
    include ::platform::params
    include ::platform::amqp::params

    file { "${glance_directory}":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${glance_directory}/image-cache":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${glance_directory}/images":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    } ->
    file { "${glance_image_conversion_dir}":
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }

    $bind_host = $::platform::network::mgmt::params::subnet_version ? {
      6       => '::',
      default => '0.0.0.0',
    }

    if $::platform::params::init_database {
      class { "::glance::db::postgresql":
        encoding => 'UTF8',
      }
    }

    include ::glance::api::authtoken
    include ::glance::registry::authtoken

    class { '::glance::registry':
      bind_host => $bind_host,
      workers   => $::platform::params::eng_workers,
    }

    # Run glance-manage to purge deleted rows daily at the 45 minute mark
    cron { 'glance-purge-deleted':
      ensure      => 'present',
      command     => '/usr/bin/glance-purge-deleted-active',
      environment => 'PATH=/bin:/usr/bin:/usr/sbin',
      minute      => '45',
      hour        => '*/24',
      user        => 'root',
    }

    cron { 'glance-cleaner':
       ensure      => 'present',
       command     => "/usr/bin/glance-cleaner --config-file /etc/glance/glance-api.conf --delete-interval $glance_delete_interval",
       environment => 'PATH=/bin:/usr/bin:/usr/sbin',
       minute      => '35',
       hour        => "*/$glance_delete_interval",
       user        => 'root',
     }

    # In glance cached mode run the pruner once every 6 hours to clean
    # stale or orphaned images
    if $::openstack::glance::params::glance_cached {
      cron { 'glance-cache-pruner':
        ensure      => 'present',
        command     => '/usr/bin/glance-cache-pruner --config-file /etc/glance/glance-api.conf',
        environment => 'PATH=/bin:/usr/bin:/usr/sbin',
        minute      => '15',
        hour        => '*/6',
        user        => 'root',
      }
    }

    class { '::glance::notify::rabbitmq':
      rabbit_use_ssl  => $::platform::amqp::params::ssl_enabled,
      default_transport_url => $::platform::amqp::params::transport_url,
    }

    if 'file' in $enabled_backends {
      include ::glance::backend::file
    }
  }
}


class openstack::glance::firewall
  inherits ::openstack::glance::params {

  platform::firewall::rule { 'glance-api':
    service_name => 'glance',
    ports => $api_port,
  }
}


class openstack::glance::haproxy
  inherits ::openstack::glance::params {

  platform::haproxy::proxy { 'glance-restapi':
    server_name => 's-glance',
    public_port => $api_port,
    private_port => $api_port,
    private_ip_address => $api_host,
  }
}


class openstack::glance::api
  inherits ::openstack::glance::params {
  include ::platform::params

  if $service_enabled {
    if ($::openstack::glance::params::service_create and 
        $::platform::params::init_keystone) {
      include ::glance::keystone::auth
    }

    include ::platform::params
    $api_workers = $::platform::params::eng_workers

    include ::platform::network::mgmt::params
    # magical hack for magical config - glance option registry_host requires brackets
    if $configured_registry_host == '0.0.0.0' {
      $registry_host = $::platform::network::mgmt::params::subnet_version ? {
        6       => '::0',
        default => '0.0.0.0',
        # TO-DO(mmagr): Add IPv6 support when hostnames are used
      }
    } else {
      $registry_host = $configured_registry_host
    }

    # enable copy-on-write cloning from glance to cinder only for rbd
    # this speeds up creation of volumes from images
    $show_image_direct_url = ('rbd' in $enabled_backends)

    if ($::platform::params::distributed_cloud_role == 'subcloud') {
      $api_use_user_token = false
    } else {
      $api_use_user_token = true
    }

    class { '::glance::api':
      bind_host             => $api_host,
      use_user_token        => $api_use_user_token,
      registry_host         => $registry_host,
      remote_registry_region_name => $remote_registry_region_name,
      workers               => $api_workers,
      sync_db   => $::platform::params::init_database,
      show_image_direct_url => $show_image_direct_url,
    }

    if 'rbd' in $enabled_backends {
        class { '::glance::backend::rbd':
          rbd_store_pool       => $rbd_store_pool,
          rbd_store_ceph_conf  => $rbd_store_ceph_conf,
        }
    }

    include ::openstack::glance::firewall
    include ::openstack::glance::haproxy
  }
}


class openstack::glance::api::reload {
  platform::sm::restart {'glance-api': }
}

class openstack::glance::api::runtime
  inherits ::openstack::glance::params {

  if $service_enabled {
    include ::openstack::glance::api

    class { '::openstack::glance::api::reload':
      stage => post
    }
  }
}
