class platform::influxdb::params (
  $bind_address = undef,
  $database = undef,
  $typesdb = undef,
  $batch_size = undef,
  $batch_pending = undef,
  $batch_timeout = undef,
  $read_buffer = undef,
) {}

class platform::influxdb
  inherits ::platform::influxdb::params {

  user { 'influxdb': ensure => present, }
  -> group { 'influxdb': ensure => present, }

  # make a pid dir for influxdb username and group
  -> file { '/var/run/influxdb':
    ensure => 'directory',
    owner  => 'influxdb',
    group  => 'influxdb',
    mode   => '0755',
  }

  # make a log dir for influxdb username and group
  -> file { '/var/log/influxdb':
    ensure => 'directory',
    owner  => 'influxdb',
    group  => 'influxdb',
    mode   => '0755',
  }

  # make a lib dir for influxdb username and group
  -> file { '/var/lib/influxdb':
    ensure => 'directory',
    owner  => 'influxdb',
    group  => 'influxdb',
    mode   => '0755',
  } # now configure influxdb

  -> file { '/etc/influxdb/influxdb.conf':
    ensure  => 'present',
    replace => true,
    content => template('platform/influxdb.conf.erb'),
  } # now make sure that influxdb is started

  -> exec { 'influxdb-enable':
      command => 'systemctl enable influxdb',
      unless  => 'systemctl is-enabled influxdb'
  }

  # ensure that influxdb is running
  -> service { 'influxdb':
    ensure   => running,
    enable   => true,
    provider => 'systemd'
  } # now ask pmon to monitor the process

  # ensure pmon soft link for process monitoring
  -> file { '/etc/pmon.d/influxdb.conf':
    ensure => 'link',
    target => '/etc/influxdb/influxdb.conf.pmon',
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }
}

class platform::influxdb::runtime {
  include ::platform::influxdb
}

class platform::influxdb::logrotate::params (
  $log_file_name = undef,
  $log_file_size = undef,
  $log_file_rotate = undef,
) {}

class platform::influxdb::logrotate
  inherits ::platform::influxdb::logrotate::params {

  file { '/etc/logrotate.d/influxdb':
    ensure  => 'present',
    replace => true,
    content => template('platform/logrotate.erb'),
  }
}
