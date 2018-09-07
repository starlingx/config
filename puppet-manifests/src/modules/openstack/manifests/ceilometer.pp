class openstack::ceilometer::params (
  $api_port = 8777,
  $region_name = undef,
  $service_name = 'openstack-ceilometer',
  $service_create = false,
) { }


class openstack::ceilometer {
  include ::platform::amqp::params
  include ::platform::params
  include ::openstack::ceilometer::params

  class { '::ceilometer':
    rabbit_use_ssl => $::platform::amqp::params::ssl_enabled,
    default_transport_url => $::platform::amqp::params::transport_url,
    rabbit_qos_prefetch_count => 100,
  }

  if ($::openstack::ceilometer::params::service_create and
      $::platform::params::init_keystone) {
    include ::ceilometer::keystone::auth

    if $::platform::params::distributed_cloud_role != 'systemcontroller' {
      include ::openstack::gnocchi::params

      class { '::ceilometer::db::sync':
        extra_params => '--skip-metering-database',
        require => [Keystone::Resource::Service_identity["ceilometer", "gnocchi"]]
      }

      if $::platform::params::vswitch_type !~ '^ovs' {
        include ::gnocchi::keystone::authtoken

        $os_auth_url = $::gnocchi::keystone::authtoken::auth_url
        $os_username = $::gnocchi::keystone::authtoken::username
        $os_user_domain = $::gnocchi::keystone::authtoken::user_domain_name
        $os_project_name = $::gnocchi::keystone::authtoken::project_name
        $os_project_domain = $::gnocchi::keystone::authtoken::project_domain_name
        $os_region_name = $::gnocchi::keystone::authtoken::region_name
        $os_auth_type = $::gnocchi::keystone::authtoken::auth_type
        $os_password = $::gnocchi::keystone::authtoken::password
        $os_interface = 'internalURL'

        Class['::ceilometer::db::sync'] ->
        exec { 'Creating vswitch resource types':
          command => 'gnocchi resource-type create vswitch_engine \
                        -a cpu_id:number:true:min=0 \
                        -a host:string:true:max_length=64;
                      gnocchi resource-type create vswitch_interface_and_port \
                        -a host:string:false:max_length=64 \
                        -a network_uuid:string:false:max_length=255 \
                        -a network_id:string:false:max_length=255 \
                        -a link-speed:number:false:min=0',
          environment => ["OS_AUTH_URL=${os_auth_url}",
                          "OS_USERNAME=${os_username}",
                          "OS_USER_DOMAIN_NAME=${os_user_domain}",
                          "OS_PROJECT_NAME=${os_project_name}",
                          "OS_PROJECT_DOMAIN_NAME=${os_project_domain}",
                          "OS_REGION_NAME=${os_region_name}",
                          "OS_INTERFACE=${os_interface}",
                          "OS_AUTH_TYPE=${os_auth_type}",
                          "OS_PASSWORD=${os_password}"],
        }
      }
    }
  }

  include ::ceilometer::agent::auth
  include ::openstack::cinder::params
  include ::openstack::glance::params

  # FIXME(mpeters): generic parameter can be moved to the puppet module
  ceilometer_config {
    'DEFAULT/executor_thread_pool_size': value => 16;
    'DEFAULT/shuffle_time_before_polling_task': value => 30;
    'DEFAULT/batch_polled_samples': value => true;
    'oslo_messaging_rabbit/rpc_conn_pool_size': value => 10;
    'oslo_messaging_rabbit/socket_timeout': value => 1.00;
    'compute/resource_update_interval': value => 60;
    'DEFAULT/region_name_for_services':  value => $::openstack::ceilometer::params::region_name;
  }


  if $::personality == 'controller' {
    include ::platform::memcached::params

    oslo::cache { 'ceilometer_config':
      enabled => true,
      backend => 'dogpile.cache.memcached',
      memcache_servers => "'${::platform::memcached::params::listen_ip}:${::platform::memcached::params::tcp_port}'",
      expiration_time => 86400,
    }
  }

  if $::platform::params::region_config {
    if $::openstack::glance::params::region_name != $::platform::params::region_2_name {
      $shared_service_glance = [$::openstack::glance::params::service_type]
    } else {
      $shared_service_glance = []
    }
    # skip the check if cinder region name has not been configured
    if ($::openstack::cinder::params::region_name != undef and
        $::openstack::cinder::params::region_name != $::platform::params::region_2_name) {
      $shared_service_cinder = [$::openstack::cinder::params::service_type, 
                                $::openstack::cinder::params::service_type_v2, 
                                $::openstack::cinder::params::service_type_v3]
    } else {
      $shared_service_cinder = []
    }
    $shared_services = concat($shared_service_glance, $shared_service_cinder)
    ceilometer_config {
      'DEFAULT/region_name_for_shared_services':  value => $::platform::params::region_1_name;
      'DEFAULT/shared_services_types': value => join($shared_services,',');
    }
  }

}


class openstack::ceilometer::agent::notification {
  include ::platform::params

  $cgcs_fs_directory    = '/opt/cgcs'
  $ceilometer_directory = "${cgcs_fs_directory}/ceilometer"
  $ceilometer_directory_csv = "${ceilometer_directory}/csv"
  $ceilometer_directory_versioned = "${ceilometer_directory}/${::platform::params::software_version}"

  file { "/etc/ceilometer/pipeline.yaml":
    ensure  => 'present',
    content => template('openstack/pipeline.yaml.erb'),
    mode    => '0640',
    owner   => 'root',
    group   => 'ceilometer',
    tag     => 'ceilometer-yamls',
  } ->
  file { "${ceilometer_directory}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } ->
  file { "${ceilometer_directory_csv}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } ->
  file { "${ceilometer_directory_versioned}":
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  } ->
  file { "${ceilometer_directory_versioned}/pipeline.yaml":
    source => '/etc/ceilometer/pipeline.yaml',
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
  }

  file { "/etc/ceilometer/gnocchi_resources.yaml":
    ensure  => 'present',
    content => template('openstack/gnocchi_resources.yaml.erb'),
    mode    => '0640',
    owner   => 'root',
    group   => 'ceilometer',
    tag     => 'ceilometer-yamls',
  }

  # Limit the number of ceilometer agent notification workers to 10 max
  $agent_workers_count = min($::platform::params::eng_workers_by_2, 10)

  if $::platform::params::system_type == 'All-in-one' {
    $batch_timeout = 25
  } else {
    $batch_timeout = 5
  }

  # FIXME(mpeters): generic parameter can be moved to the puppet module
  ceilometer_config {
    'DEFAULT/csv_location': value => "${ceilometer_directory_csv}";
    'DEFAULT/csv_location_strict': value => true;
    'notification/workers': value => $agent_workers_count;
    'notification/batch_size': value => 100;
    'notification/batch_timeout': value => $batch_timeout;
  }
}


class openstack::ceilometer::polling (
  $instance_polling_interval       = 600,
  $instance_cpu_polling_interval   = 30,
  $instance_disk_polling_interval  = 600,
  $ipmi_polling_interval           = 600,
  $ceph_polling_interval           = 600,
  $image_polling_interval          = 600,
  $volume_polling_interval         = 600,
) {
   include ::platform::params

   file { "/etc/ceilometer/polling.yaml":
     ensure  => 'present',
     content => template('openstack/polling.yaml.erb'),
     mode    => '0640',
     owner   => 'root',
     group   => 'ceilometer',
     tag     => 'ceilometer-yamls',
   }

   if $::personality == 'controller' {
     $central_namespace = true
   } else {
     $central_namespace = false
   }

   if str2bool($::disable_compute_services) {
     $agent_enable = false
     $compute_namespace = false

     file { '/etc/pmon.d/ceilometer-polling.conf':
        ensure  => absent,
     }
   } else {
     $agent_enable = true

     if str2bool($::is_compute_subfunction) {
       $pmon_target = "/etc/ceilometer/ceilometer-polling-compute.conf.pmon"
       $compute_namespace = true
     } else {
       $pmon_target = "/etc/ceilometer/ceilometer-polling.conf.pmon"
       $compute_namespace = false
     }

     file { "/etc/pmon.d/ceilometer-polling.conf":
       ensure => link,
       target => $pmon_target,
       owner   => 'root',
       group   => 'root',
       mode    => '0640',
     }
   }

   class { '::ceilometer::agent::polling':
     enabled => $agent_enable,
     central_namespace => $central_namespace,
     compute_namespace => $compute_namespace,
   }
}
