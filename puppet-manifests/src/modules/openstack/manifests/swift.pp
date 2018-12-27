class openstack::swift::params (
  $swift_hash_path_suffix = 'swift_secret',
  $service_name = 'openstack-swift',
  $service_enabled = false,
  $api_port = 8080,
  $api_host = '127.0.0.1',
  $fs_size_mb = '25',
) { }


class openstack::swift::firewall
  inherits ::openstack::swift::params {

  platform::firewall::rule { 'swift-api':
    service_name => 'swift',
    ports        => $api_port,
  }
}


class openstack::swift::haproxy
  inherits ::openstack::swift::params {

  platform::haproxy::proxy { 'swift-restapi':
    server_name  => 's-swift',
    public_port  => $api_port,
    private_port => $api_port,
  }
}


class openstack::swift::api {
  include ::openstack::swift::firewall
  include ::openstack::swift::haproxy
}


class openstack::swift
  inherits ::openstack::swift::params {

  include ::platform::params
  include ::openstack::keystone::params

  if $service_enabled {
    if str2bool($::is_controller_active) or
        str2bool($::is_standalone_controller) {
      class { '::swift::keystone::auth':
        configure_s3_endpoint => false,
      }
    }

    class { '::swift':
      swift_hash_path_suffix => $swift_hash_path_suffix
    }

    include swift::proxy::healthcheck
    include swift::proxy::proxy_logging
    include swift::proxy::authtoken
    include swift::proxy::keystone
    include swift::proxy::container_quotas
    class { 'swift::proxy':
      account_autocreate => true,
      proxy_local_net_ip => $api_host,
      port               => $api_port,
      pipeline           => ['healthcheck', 'authtoken', 'keystone', 'container-quotas' , 'proxy-logging', 'proxy-server'],
    }

    swift::storage::loopback { '1':
      require      => Class['swift'],
      base_dir     => '/srv/loopback-device',
      mnt_base_dir => '/srv/node',
      byte_size    => '1024',
      seek         => $fs_size_mb*1024,
    }

    # remove dependency on xinetd
    class { '::rsync::server':
      use_xinetd => false,
      address    => $api_host,
      use_chroot => 'no',
    }

    class { 'swift::storage::all':
      storage_local_net_ip => $api_host,
      object_port          => '6200',
      container_port       => '6201',
      account_port         => '6202',
      account_pipeline     => ['healthcheck', 'recon', 'account-server'],
      container_pipeline   => ['healthcheck', 'recon', 'container-server'],
      object_pipeline      => ['healthcheck', 'recon', 'object-server'],
      # Turn on support for object versioning
      allow_versions       => true,
    }

    $rings = [
      'account',
      'object',
      'container']
    swift::storage::filter::recon { $rings: }
    swift::storage::filter::healthcheck { $rings: }

    ring_object_device { "${api_host}:6200/1":
      region => 1, # optional, defaults to 1
      zone   => 1,
      weight => 1,
    }

    ring_container_device { "${api_host}:6201/1":
      zone   => 1,
      weight => 1,
    }

    ring_account_device { "${api_host}:6202/1":
      zone   => 1,
      weight => 1,
    }

    class { 'swift::ringbuilder':
      part_power     => '10',
      # number of replicas can not be more than the number of nodes
      replicas       => '1',
      min_part_hours => '1',
      require        => Class['swift'],
    }
  }
}


class openstack::swift::runtime {
  include ::openstack::swift
}
