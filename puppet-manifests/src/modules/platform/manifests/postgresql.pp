class platform::postgresql::params
  inherits ::platform::params {

  $root_dir = '/var/lib/postgresql'
  $config_dir = '/etc/postgresql'

  $data_dir = "${root_dir}/${::platform::params::software_version}"

  $password = undef
}


class platform::postgresql::server (
  $ipv4acl = undef,
) inherits ::platform::postgresql::params {

  include ::platform::params

  # Set up autovacuum
  postgresql::server::config_entry { 'track_counts':
    value => 'on',
  }
  postgresql::server::config_entry { 'autovacuum':
    value => 'on',
  }
  # Only log autovacuum calls that are slow
  postgresql::server::config_entry { 'log_autovacuum_min_duration':
    value => '100',
  }
  # Make autovacuum more aggressive
  postgresql::server::config_entry { 'autovacuum_max_workers':
    value => '5',
  }
  postgresql::server::config_entry { 'autovacuum_vacuum_scale_factor':
    value => '0.05',
  }
  postgresql::server::config_entry { 'autovacuum_analyze_scale_factor':
    value => '0.1',
  }
  postgresql::server::config_entry { 'autovacuum_vacuum_cost_delay':
    value => '-1',
  }
  postgresql::server::config_entry { 'autovacuum_vacuum_cost_limit':
    value => '-1',
  }

  # Set up logging
  postgresql::server::config_entry { 'log_destination':
    value => 'syslog',
  }
  postgresql::server::config_entry { 'syslog_facility':
    value => 'LOCAL0',
  }

  # log postgres operations that exceed 1 second
  postgresql::server::config_entry { 'log_min_duration_statement':
    value => '1000',
  }

  # Set large values for postgres in normal mode
  # In AIO or virtual box, use reduced settings
  #

  # Normal mode
  # 1500 connections
  # 80 MB shared buffer
  # work_mem 512 MB since some ceilometer queries entail extensive
  # sorting as well as hash joins and hash based aggregation.
  # checkpoint_segments increased to reduce frequency of checkpoints
  if str2bool($::is_compute_subfunction) or str2bool($::is_virtual) {
    # AIO or virtual box
    # 700 connections needs about 80MB shared buffer
    # Leave work_mem as the default for vbox and AIO
    # Leave checkpoint_segments as the default for vbox and AIO
    postgresql::server::config_entry { 'max_connections':
      value => '700',
    }
    postgresql::server::config_entry { 'shared_buffers':
      value => '80MB',
    }
  } else {
    postgresql::server::config_entry { 'max_connections':
      value => '1500',
    }
    postgresql::server::config_entry { 'shared_buffers':
      value => '80MB',
    }
    postgresql::server::config_entry { 'work_mem':
      value => '512MB',
    }
    postgresql::server::config_entry { 'checkpoint_segments':
      value => '10',
    }
  }

  if str2bool($::is_initial_config_primary) {
    $service_ensure = 'running'

    # ensure service is stopped after initial configuration
    class { '::platform::postgresql::post':
      stage => post
    }
  } else {
    $service_ensure = 'stopped'
  }

  class {"::postgresql::globals":
    datadir => $data_dir,
    confdir => $config_dir,
  } ->

  class {"::postgresql::server":
    ip_mask_allow_all_users => $ipv4acl,
    service_ensure => $service_ensure,
  }
}


class platform::postgresql::post {
  # postgresql needs to be running in order to apply the initial manifest,
  # however, it needs to be stopped/disabled to allow SM to manage the service.
  # To allow for the transition it must be explicitely stopped. Once puppet
  # can directly handle SM managed services, then this can be removed.
  exec { 'stop postgresql service':
    command => "systemctl stop postgresql; systemctl disable postgresql",
  }
}


class platform::postgresql::bootstrap
  inherits ::platform::postgresql::params {

  Class['::platform::drbd::pgsql'] -> Class[$name]

  exec { 'Empty pg dir':
    command => "rm -fR ${root_dir}/*",
  } ->

  exec { 'Create pg datadir':
    command => "mkdir -p ${data_dir}",
  } ->

  exec { 'Change pg dir permissions':
    command => "chown -R postgres:postgres ${root_dir}",
  } ->

  file_line { 'allow sudo with no tty':
    path  => '/etc/sudoers',
    match => '^Defaults *requiretty',
    line  => '#Defaults    requiretty',
  } ->

  exec { 'Create pg database':
    command => "sudo -u postgres initdb -D ${data_dir}",
  } ->

  exec { 'Move Config files':
    command => "mkdir -p ${config_dir} && mv ${data_dir}/*.conf ${config_dir}/ && ln -s ${config_dir}/*.conf ${data_dir}/",
  } ->

  class {"::postgresql::globals":
    datadir => $data_dir,
    confdir => $config_dir,
  } ->

  class {"::postgresql::server":
  }

  # Allow local postgres user as trusted for simplex upgrade scripts
  postgresql::server::pg_hba_rule { 'postgres trusted local access':
    type        => 'local',
    user        => 'postgres',
    auth_method => 'trust',
    database    => 'all',
    order       => '000',
  }

  postgresql::server::role {'admin':
    password_hash => 'admin',
    superuser     => true,
  }
}

class platform::postgresql::upgrade
  inherits ::platform::postgresql::params {

  exec { 'Move Config files':
    command => "mkdir -p ${config_dir} && mv ${data_dir}/*.conf ${config_dir}/ && ln -s ${config_dir}/*.conf ${data_dir}/",
  } ->

  class {"::postgresql::globals":
    datadir => $data_dir,
    confdir => $config_dir,
    needs_initdb => false,
  } ->

  class {"::postgresql::server":
  }

  include ::aodh::db::postgresql
  include ::cinder::db::postgresql
  include ::glance::db::postgresql
  include ::gnocchi::db::postgresql
  include ::heat::db::postgresql
  include ::murano::db::postgresql
  include ::magnum::db::postgresql
  include ::neutron::db::postgresql
  include ::nova::db::postgresql
  include ::nova::db::postgresql_api
  include ::panko::db::postgresql
  include ::sysinv::db::postgresql
  include ::keystone::db::postgresql
  include ::ironic::db::postgresql
  include ::fm::db::postgresql

}

