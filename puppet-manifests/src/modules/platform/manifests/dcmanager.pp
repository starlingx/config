class platform::dcmanager::params (
  $api_port = 8119,
  $region_name = undef,
  $domain_name = undef,
  $domain_admin = undef,
  $domain_pwd = undef,
  $service_name = 'dcmanager',
  $default_endpoint_type = "internalURL",
  $service_create = false,
) {
  include ::platform::params

  include ::platform::network::mgmt::params
  $api_host = $::platform::network::mgmt::params::controller_address
}


class platform::dcmanager
  inherits ::platform::dcmanager::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::platform::params 
    include ::platform::amqp::params

    if $::platform::params::init_database {
      include ::dcmanager::db::postgresql
    }

    class { '::dcmanager':
      rabbit_host => $::platform::amqp::params::host_url,
      rabbit_port => $::platform::amqp::params::port,
      rabbit_userid => $::platform::amqp::params::auth_user,
      rabbit_password => $::platform::amqp::params::auth_password,
    }
  }
}


class platform::dcmanager::firewall
  inherits ::platform::dcmanager::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {  
    platform::firewall::rule { 'dcmanager-api':
      service_name => 'dcmanager',
      ports        => $api_port,
    }
  }
}


class platform::dcmanager::haproxy
  inherits ::platform::dcmanager::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    platform::haproxy::proxy { 'dcmanager-restapi':
      server_name => 's-dcmanager',
      public_port => $api_port,
      private_port => $api_port,
    }
  }
}

class platform::dcmanager::manager {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    include ::dcmanager::manager
  }
}

class platform::dcmanager::api
  inherits ::platform::dcmanager::params {
  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    if ($::platform::dcmanager::params::service_create and
        $::platform::params::init_keystone) {
      include ::dcmanager::keystone::auth
    }

    class { '::dcmanager::api':
      bind_host => $api_host,
    }
  

    include ::platform::dcmanager::firewall
    include ::platform::dcmanager::haproxy
  }
}
