class platform::ceph::params(
  $service_enabled = false,
  $cluster_uuid = undef,
  $cluster_name = 'ceph',
  $authentication_type = 'none',
  $mon_lv_name = 'ceph-mon-lv',
  $mon_lv_size = 0,
  $mon_fs_type = 'ext4',
  $mon_fs_options = ' ',
  $mon_mountpoint = '/var/lib/ceph/mon',
  $mon_0_host = undef,
  $mon_0_ip = undef,
  $mon_0_addr = undef,
  $mon_1_host = undef,
  $mon_1_ip = undef,
  $mon_1_addr = undef,
  $mon_2_host = undef,
  $mon_2_ip = undef,
  $mon_2_addr = undef,
  $rgw_enabled = false,
  $rgw_client_name = 'radosgw.gateway',
  $rgw_user_name = 'root',
  $rgw_frontend_type = 'civetweb',
  $rgw_port = 7480,
  $rgw_log_file = '/var/log/radosgw/radosgw.log',
  $rgw_admin_domain = undef,
  $rgw_admin_project = undef,
  $rgw_admin_user = 'swift',
  $rgw_admin_password = undef,
  $rgw_max_put_size = '53687091200',
  $rgw_gc_max_objs = '977',
  $rgw_gc_obj_min_wait = '600',
  $rgw_gc_processor_max_time = '300',
  $rgw_gc_processor_period = '300',
  $configure_ceph_mon_info = false,
  $ceph_config_ready_path = '/var/run/.ceph_started',
) { }


class platform::ceph
  inherits ::platform::ceph::params {

  if $service_enabled or $configure_ceph_mon_info {
    class { '::ceph':
      fsid => $cluster_uuid,
      authentication_type => $authentication_type,
    } ->
    ceph_config {
      "mon.${mon_0_host}/host":      value => $mon_0_host;
      "mon.${mon_0_host}/mon_addr":  value => $mon_0_addr;
      "mon.${mon_1_host}/host":      value => $mon_1_host;
      "mon.${mon_1_host}/mon_addr":  value => $mon_1_addr;
      "mon.${mon_2_host}/host":      value => $mon_2_host;
      "mon.${mon_2_host}/mon_addr":  value => $mon_2_addr;
      "mon/mon clock drift allowed": value => ".1";
    }
  }

  class { '::platform::ceph::post':
    stage => post
  }
}


class platform::ceph::post {
  include ::platform::ceph::params
  # Enable ceph process recovery after all configuration is done
  file { $::platform::ceph::params::ceph_config_ready_path:
    ensure => present,
    content => '',
    owner => 'root',
    group => 'root',
    mode => '0644',
  }
}


class platform::ceph::monitor
  inherits ::platform::ceph::params {

  if $service_enabled {
    file { '/var/lib/ceph':
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
    } ->

    platform::filesystem { $mon_lv_name:
      lv_name    => $mon_lv_name,
      lv_size    => $mon_lv_size,
      mountpoint => $mon_mountpoint,
      fs_type    => $mon_fs_type,
      fs_options => $mon_fs_options,
    } -> Class['::ceph']

    file { "/etc/pmon.d/ceph.conf":
      ensure  => link,
      target  => "/etc/ceph/ceph.conf.pmon",
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
    }

    # ensure configuration is complete before creating monitors
    Class['::ceph'] -> Ceph::Mon <| |>

    # On active controller ensure service is started to
    # allow in-service configuration.
    # TODO(oponcea): Remove the pmon flag file created by systemctl start ceph
    if str2bool($::is_controller_active) {
      $service_ensure = "running"
    } else {
      $service_ensure = "stopped"
    }

    # default configuration for all ceph monitor resources
    Ceph::Mon {
      fsid => $cluster_uuid,
      authentication_type => $authentication_type,
      service_ensure => $service_ensure,
    }

    if $::hostname == $mon_0_host {
      ceph::mon { $mon_0_host:
        public_addr => $mon_0_ip,
      }
    }
    elsif $::hostname == $mon_1_host {
      ceph::mon { $mon_1_host:
        public_addr => $mon_1_ip,
      }
    }
    elsif $::hostname == $mon_2_host {
      ceph::mon { $mon_2_host:
        public_addr => $mon_2_ip,
      }
    }
  }
}


define platform_ceph_osd(
  $osd_id,
  $osd_uuid,
  $disk_path,
  $data_path,
  $journal_path,
  $tier_name,
) {
  # Only set the crush location for additional tiers
  if $tier_name != 'storage' {
    ceph_config {
      "osd.${$osd_id}/host":           value => "${$::platform::params::hostname}-${$tier_name}";
      "osd.${$osd_id}/crush_location": value => "root=${tier_name}-tier host=${$::platform::params::hostname}-${$tier_name}";
    }
  }
  file { "/var/lib/ceph/osd/ceph-${osd_id}":
    ensure => 'directory',
    owner => 'root',
    group => 'root',
    mode => '0755',
  } ->
  ceph::osd { $disk_path:
    uuid => $osd_uuid,
  } ->
  exec { "configure journal location ${name}":
    logoutput => true,
    command => template('platform/ceph.journal.location.erb')
  }
}


define platform_ceph_journal(
  $disk_path,
  $journal_sizes,
) {
  exec { "configure journal partitions ${name}":
    logoutput => true,
    command => template('platform/ceph.journal.partitions.erb')
  }
}


class platform::ceph::storage(
  $osd_config = {},
  $journal_config = {},
) inherits ::platform::ceph::params {

  # Ensure partitions update prior to ceph storage configuration
  Class['::platform::partitions'] -> Class[$name]

  file { '/var/lib/ceph/osd':
    path   => '/var/lib/ceph/osd',
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # Journal disks need to be prepared before the OSDs are configured
  Platform_ceph_journal <| |> -> Platform_ceph_osd <| |>

  # default configuration for all ceph object resources
  Ceph::Osd {
    cluster => $cluster_name,
    cluster_uuid => $cluster_uuid,
  }

  create_resources('platform_ceph_osd', $osd_config)
  create_resources('platform_ceph_journal', $journal_config)
}


class platform::ceph::firewall
  inherits ::platform::ceph::params {

  if $rgw_enabled {
    platform::firewall::rule { 'ceph-radosgw':
      service_name => 'ceph-radosgw',
      ports        => $rgw_port,
    }
  }
}


class platform::ceph::haproxy
  inherits ::platform::ceph::params {

  if $rgw_enabled {
    platform::haproxy::proxy { 'ceph-radosgw-restapi':
      server_name  => 's-ceph-radosgw',
      public_port  => $rgw_port,
      private_port => $rgw_port,
    }
  }
}

class platform::ceph::rgw
  inherits ::platform::ceph::params {

  if $rgw_enabled {
    include ::platform::params

    include ::openstack::keystone::params
    $auth_host = $::openstack::keystone::params::host_url

    if ($::platform::params::init_keystone and
        !$::platform::params::region_config) {
      include ::platform::ceph::rgw::keystone::auth
    }

    ceph::rgw { $rgw_client_name:
      user          => $rgw_user_name,
      frontend_type => $rgw_frontend_type,
      rgw_frontends => "${rgw_frontend_type} port=${auth_host}:${rgw_port}",
      # service is managed by SM
      rgw_enable    => false,
      # The location of the log file shoule be the same as what's specified in
      # /etc/logrotate.d/radosgw in order for log rotation to work properly
      log_file      => $rgw_log_file,
    }

    ceph::rgw::keystone { $rgw_client_name:
      # keystone admin token is disabled after initial keystone configuration
      # for security reason. Use keystone service tenant credentials instead.
      rgw_keystone_admin_token    => '',
      rgw_keystone_url            => $::openstack::keystone::params::auth_uri,
      rgw_keystone_version        => $::openstack::keystone::params::api_version,
      rgw_keystone_accepted_roles => 'admin,_member_',
      use_pki                     => false,
      rgw_keystone_admin_domain   => $rgw_admin_domain,
      rgw_keystone_admin_project  => $rgw_admin_project,
      rgw_keystone_admin_user     => $rgw_admin_user,
      rgw_keystone_admin_password => $rgw_admin_password,
    }

    ceph_config {
      # increase limit for single operation uploading to 50G (50*1024*1024*1024)
      "client.$rgw_client_name/rgw_max_put_size": value => $rgw_max_put_size;
      # increase frequency and scope of garbage collection
      "client.$rgw_client_name/rgw_gc_max_objs": value => $rgw_gc_max_objs;
      "client.$rgw_client_name/rgw_gc_obj_min_wait": value => $rgw_gc_obj_min_wait;
      "client.$rgw_client_name/rgw_gc_processor_max_time": value => $rgw_gc_processor_max_time;
      "client.$rgw_client_name/rgw_gc_processor_period": value => $rgw_gc_processor_period;
    }
  }

  include ::platform::ceph::firewall
  include ::platform::ceph::haproxy
}


class platform::ceph::rgw::keystone::auth(
  $password,
  $auth_name = 'swift',
  $tenant = 'services',
  $email = 'swift@localhost',
  $region = 'RegionOne',
  $service_name = 'swift',
  $service_description = 'Openstack Object-Store Service',
  $configure_endpoint= true,
  $configure_user = true,
  $configure_user_role = true,
  $public_url = 'http://127.0.0.1:8080/swift/v1',
  $admin_url = 'http://127.0.0.1:8080/swift/v1',
  $internal_url = 'http://127.0.0.1:8080/swift/v1',
) {
  # create a swift compatible endpoint for the object-store service
  keystone::resource::service_identity { 'swift':
    configure_endpoint  => $configure_endpoint,
    configure_user      => $configure_user,
    configure_user_role => $configure_user_role,
    service_name        => $service_name,
    service_type        => 'object-store',
    service_description => $service_description,
    region              => $region,
    auth_name           => $auth_name,
    password            => $password,
    email               => $email,
    tenant              => $tenant,
    public_url          => $public_url,
    admin_url           => $admin_url,
    internal_url        => $internal_url,
  }
}


class platform::ceph::controller::runtime {
  include ::platform::ceph::monitor
  include ::platform::ceph
}

class platform::ceph::compute::runtime {
  include ::platform::ceph
}
