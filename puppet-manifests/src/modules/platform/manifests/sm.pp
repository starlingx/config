class platform::sm::params (
  $mgmt_ip_multicast = undef,
  $infra_ip_multicast = undef,
) { }

class platform::sm
  inherits ::platform::sm::params {

  include ::platform::params
  $controller_0_hostname         = $::platform::params::controller_0_hostname
  $controller_1_hostname         = $::platform::params::controller_1_hostname
  $platform_sw_version           = $::platform::params::software_version
  $region_config                 = $::platform::params::region_config
  $region_2_name                 = $::platform::params::region_2_name
  $system_mode                   = $::platform::params::system_mode

  include ::platform::network::pxeboot::params
  if $::platform::network::pxeboot::params::interface_name {
    $pxeboot_ip_interface = $::platform::network::pxeboot::params::interface_name
  } else {
    # Fallback to using the management interface for PXE boot network
    $pxeboot_ip_interface = $::platform::network::mgmt::params::interface_name
  }
  $pxeboot_ip_param_ip           = $::platform::network::pxeboot::params::controller_address
  $pxeboot_ip_param_mask         = $::platform::network::pxeboot::params::subnet_prefixlen

  include ::platform::network::mgmt::params
  $mgmt_ip_interface             = $::platform::network::mgmt::params::interface_name
  $mgmt_ip_param_ip              = $::platform::network::mgmt::params::controller_address
  $mgmt_ip_param_mask            = $::platform::network::mgmt::params::subnet_prefixlen

  include ::platform::network::infra::params
  $infra_ip_interface            = $::platform::network::infra::params::interface_name

  include ::platform::network::oam::params
  $oam_ip_interface              = $::platform::network::oam::params::interface_name
  $oam_ip_param_ip               = $::platform::network::oam::params::controller_address
  $oam_ip_param_mask             = $::platform::network::oam::params::subnet_prefixlen

  include ::platform::drbd::cgcs::params
  $cgcs_drbd_resource            = $::platform::drbd::cgcs::params::resource_name
  $cgcs_fs_device                = $::platform::drbd::cgcs::params::device
  $cgcs_fs_directory             = $::platform::drbd::cgcs::params::mountpoint

  include ::platform::drbd::pgsql::params
  $pg_drbd_resource              = $::platform::drbd::pgsql::params::resource_name
  $pg_fs_device                  = $::platform::drbd::pgsql::params::device
  $pg_fs_directory               = $::platform::drbd::pgsql::params::mountpoint
  $pg_data_dir                   = "${pg_fs_directory}/${platform_sw_version}"

  include ::platform::drbd::platform::params
  $platform_drbd_resource        = $::platform::drbd::platform::params::resource_name
  $platform_fs_device            = $::platform::drbd::platform::params::device
  $platform_fs_directory         = $::platform::drbd::platform::params::mountpoint

  include ::platform::drbd::rabbit::params
  $rabbit_drbd_resource          = $::platform::drbd::rabbit::params::resource_name
  $rabbit_fs_device              = $::platform::drbd::rabbit::params::device
  $rabbit_fs_directory           = $::platform::drbd::rabbit::params::mountpoint

  include ::platform::drbd::extension::params
  $extension_drbd_resource          = $::platform::drbd::extension::params::resource_name
  $extension_fs_device              = $::platform::drbd::extension::params::device
  $extension_fs_directory           = $::platform::drbd::extension::params::mountpoint

  include ::platform::drbd::patch_vault::params
  $drbd_patch_enabled           = $::platform::drbd::patch_vault::params::service_enabled
  $patch_drbd_resource          = $::platform::drbd::patch_vault::params::resource_name
  $patch_fs_device              = $::platform::drbd::patch_vault::params::device
  $patch_fs_directory           = $::platform::drbd::patch_vault::params::mountpoint

  include ::platform::drbd::etcd::params
  $etcd_drbd_resource           = $::platform::drbd::etcd::params::resource_name
  $etcd_fs_device               = $::platform::drbd::etcd::params::device
  $etcd_fs_directory            = $::platform::drbd::etcd::params::mountpoint

  include ::platform::drbd::dockerdistribution::params
  $dockerdistribution_drbd_resource          = $::platform::drbd::dockerdistribution::params::resource_name
  $dockerdistribution_fs_device              = $::platform::drbd::dockerdistribution::params::device
  $dockerdistribution_fs_directory           = $::platform::drbd::dockerdistribution::params::mountpoint

  include ::openstack::keystone::params
  $keystone_api_version          = $::openstack::keystone::params::api_version
  $keystone_identity_uri         = $::openstack::keystone::params::identity_uri
  $keystone_host_url             = $::openstack::keystone::params::host_url
  $keystone_region               = $::openstack::keystone::params::region_name

  include ::platform::amqp::params
  $amqp_server_port              = $::platform::amqp::params::port
  $rabbit_node_name              = $::platform::amqp::params::node
  $rabbit_mnesia_base            = "/var/lib/rabbitmq/${platform_sw_version}/mnesia"
  $murano_rabbit_node_name       = "murano-$rabbit_node_name"
  $murano_rabbit_mnesia_base     = "/var/lib/rabbitmq/murano/${platform_sw_version}/mnesia"
  $murano_rabbit_config_file     = "/etc/rabbitmq/murano-rabbitmq"

  include ::platform::ldap::params
  $ldapserver_remote             = $::platform::ldap::params::ldapserver_remote

  # This variable is used also in create_sm_db.sql.
  # please change that one as well when modifying this variable
  $rabbit_pid              = "/var/run/rabbitmq/rabbitmq.pid"
  $murano_rabbit_env_config_file  = "/etc/rabbitmq/murano-rabbitmq-env.conf"

  $murano_rabbit_pid              = "/var/run/rabbitmq/murano-rabbit.pid"
  $murano_rabbit_dist_port        = 25673

  $rabbitmq_server = '/usr/lib/rabbitmq/bin/rabbitmq-server'
  $rabbitmqctl     = '/usr/lib/rabbitmq/bin/rabbitmqctl'

  include ::platform::kubernetes::params
  $kubernetes_enabled             = $::platform::kubernetes::params::enabled

  ############ NFS Parameters ################

  # Platform NFS network is over the management network
  $platform_nfs_ip_interface   = $::platform::network::mgmt::params::interface_name
  $platform_nfs_ip_param_ip    = $::platform::network::mgmt::params::platform_nfs_address
  $platform_nfs_ip_param_mask  = $::platform::network::mgmt::params::subnet_prefixlen
  $platform_nfs_ip_network_url = $::platform::network::mgmt::params::subnet_network_url

  # CGCS NFS network is over the infrastructure network if configured
  if $infra_ip_interface {
    $cgcs_nfs_ip_interface   = $::platform::network::infra::params::interface_name
    $cgcs_nfs_ip_param_ip    = $::platform::network::infra::params::cgcs_nfs_address
    $cgcs_nfs_ip_network_url = $::platform::network::infra::params::subnet_network_url
    $cgcs_nfs_ip_param_mask  = $::platform::network::infra::params::subnet_prefixlen

    $cinder_ip_interface     = $::platform::network::infra::params::interface_name
    $cinder_ip_param_mask    = $::platform::network::infra::params::subnet_prefixlen
  } else {
    $cgcs_nfs_ip_interface   = $::platform::network::mgmt::params::interface_name
    $cgcs_nfs_ip_param_ip    = $::platform::network::mgmt::params::cgcs_nfs_address
    $cgcs_nfs_ip_network_url = $::platform::network::mgmt::params::subnet_network_url
    $cgcs_nfs_ip_param_mask  = $::platform::network::mgmt::params::subnet_prefixlen

    $cinder_ip_interface     = $::platform::network::mgmt::params::interface_name
    $cinder_ip_param_mask    = $::platform::network::mgmt::params::subnet_prefixlen
  }

  $platform_nfs_subnet_url = "${platform_nfs_ip_network_url}/${platform_nfs_ip_param_mask}"
  $cgcs_nfs_subnet_url = "${cgcs_nfs_ip_network_url}/${cgcs_nfs_ip_param_mask}"

  $nfs_server_mgmt_exports = "${cgcs_nfs_subnet_url}:${cgcs_fs_directory},${platform_nfs_subnet_url}:${platform_fs_directory},${platform_nfs_subnet_url}:${extension_fs_directory}"
  $nfs_server_mgmt_mounts  = "${cgcs_fs_device}:${cgcs_fs_directory},${platform_fs_device}:${platform_fs_directory},${extension_fs_device}:${extension_fs_directory}"

  ################## Openstack Parameters ######################

  # Keystone
  if $region_config {
    $os_mgmt_ip             = $keystone_identity_uri
    $os_keystone_auth_url   = "${os_mgmt_ip}/${keystone_api_version}"
    $os_region_name         = $region_2_name
  } else {
    $os_auth_ip             = $keystone_host_url
    $os_keystone_auth_url   = "http://${os_auth_ip}:5000/${keystone_api_version}"
    $os_region_name         = $keystone_region
  }

  $ost_cl_ctrl_host         = $::platform::network::mgmt::params::controller_address_url

  include ::openstack::client::params

  $os_username              = $::openstack::client::params::admin_username
  $os_project_name          = 'admin'
  $os_auth_url              = $os_keystone_auth_url
  $system_url               = "http://${ost_cl_ctrl_host}:6385"
  $os_user_domain_name      = $::openstack::client::params::admin_user_domain
  $os_project_domain_name   = $::openstack::client::params::admin_project_domain

  # Nova
  $db_server_port           = '5432'

  include ::openstack::nova::params
  $novnc_console_port       = $::openstack::nova::params::nova_novnc_port

  # Heat
  include ::openstack::heat::params
  $heat_api_cfn_port        = $::openstack::heat::params::cfn_port
  $heat_api_cloudwatch_port = $::openstack::heat::params::cloudwatch_port
  $heat_api_port            = $::openstack::heat::params::api_port

  # Neutron
  include ::openstack::neutron::params
  $neutron_region_name = $::openstack::neutron::params::region_name
  $neutron_plugin_config = "/etc/neutron/plugin.ini"
  $neutron_sriov_plugin_config = "/etc/neutron/plugins/ml2/ml2_conf_sriov.ini"

  # Cinder
  include ::openstack::cinder::params
  $cinder_service_enabled = $::openstack::cinder::params::service_enabled
  $cinder_region_name     = $::openstack::cinder::params::region_name
  $cinder_ip_param_ip     = $::openstack::cinder::params::cinder_address
  $cinder_backends        = $::openstack::cinder::params::enabled_backends
  $cinder_drbd_resource   = $::openstack::cinder::params::drbd_resource
  $cinder_vg_name         = $::openstack::cinder::params::cinder_vg_name

  # Glance
  include ::openstack::glance::params
  $glance_region_name = $::openstack::glance::params::region_name
  $glance_cached = $::openstack::glance::params::glance_cached

  # Murano
  include ::openstack::murano::params
  $disable_murano_agent = $::openstack::murano::params::disable_murano_agent

  # Magnum
  include ::openstack::magnum::params

  # Ironic
  include ::openstack::ironic::params
  $ironic_tftp_ip = $::openstack::ironic::params::tftp_server
  $ironic_controller_0_nic = $::openstack::ironic::params::controller_0_if
  $ironic_controller_1_nic = $::openstack::ironic::params::controller_1_if
  $ironic_netmask = $::openstack::ironic::params::netmask
  $ironic_tftproot = $::openstack::ironic::params::ironic_tftpboot_dir

  # Ceph-Rados-Gateway
  include ::platform::ceph::params
  $ceph_configured = $::platform::ceph::params::service_enabled
  $rgw_configured = $::platform::ceph::params::rgw_enabled

  # Gnocchi
  include ::openstack::gnocchi::params

  # AODH
  include ::openstack::aodh::params

  # Panko
  include ::openstack::panko::params

  if $system_mode == 'simplex' {
    $hostunit = '0'
    $management_my_unit_ip   = $::platform::network::mgmt::params::controller0_address
    $oam_my_unit_ip          = $::platform::network::oam::params::controller_address
  } else {
    case $::hostname {
      $controller_0_hostname: {
        $hostunit = '0'
        $management_my_unit_ip   = $::platform::network::mgmt::params::controller0_address
        $management_peer_unit_ip = $::platform::network::mgmt::params::controller1_address
        $oam_my_unit_ip          = $::platform::network::oam::params::controller0_address
        $oam_peer_unit_ip        = $::platform::network::oam::params::controller1_address
        $infra_my_unit_ip        = $::platform::network::infra::params::controller0_address
        $infra_peer_unit_ip      = $::platform::network::infra::params::controller1_address
      }
      $controller_1_hostname: {
        $hostunit = '1'
        $management_my_unit_ip   = $::platform::network::mgmt::params::controller1_address
        $management_peer_unit_ip = $::platform::network::mgmt::params::controller0_address
        $oam_my_unit_ip          = $::platform::network::oam::params::controller1_address
        $oam_peer_unit_ip        = $::platform::network::oam::params::controller0_address
        $infra_my_unit_ip        = $::platform::network::infra::params::controller1_address
        $infra_peer_unit_ip      = $::platform::network::infra::params::controller0_address
      }
      default: {
        $hostunit = '2'
        $management_my_unit_ip = undef
        $management_peer_unit_ip = undef
        $oam_my_unit_ip = undef
        $oam_peer_unit_ip = undef
        $infra_my_unit_ip = undef
        $infra_peer_unit_ip = undef
      }
    }
  }


  # Add a shell for the postgres. By default WRL sets the shell to /bin/false.
  user { 'postgres':
    shell => '/bin/sh'
  }

  # Workaround for the time being to prevent SM from enabling the openstack
  # services when kubernetes is enabled to avoid making changes to individual
  # openstack manifests
  if $kubernetes_enabled {
    $heat_service_enabled   = false
    $murano_configured = false
    $ironic_configured = false
    $magnum_configured = false
    $gnocchi_enabled   = false
    $aodh_enabled      = false
    $panko_enabled     = false
  } else {
      $heat_service_enabled   = $::openstack::heat::params::service_enabled
      $murano_configured      = $::openstack::murano::params::service_enabled
      $ironic_configured      = $::openstack::ironic::params::service_enabled
      $magnum_configured      = $::openstack::magnum::params::service_enabled
      $gnocchi_enabled        = $::openstack::gnocchi::params::service_enabled
      $aodh_enabled           = $::openstack::aodh::params::service_enabled
      $panko_enabled          = $::openstack::panko::params::service_enabled
  }

  if $system_mode == 'simplex' {
    exec { 'Deprovision oam-ip service group member':
      command => "sm-deprovision service-group-member oam-services oam-ip",
    } ->
    exec { 'Deprovision oam-ip service':
      command => "sm-deprovision service oam-ip",
    }

    exec { 'Configure OAM Interface':
      command => "sm-configure interface controller oam-interface \"\" ${oam_my_unit_ip} 2222 2223 \"\" 2222 2223",
    }

    exec { 'Configure Management Interface':
      command => "sm-configure interface controller management-interface ${mgmt_ip_multicast} ${management_my_unit_ip} 2222 2223 \"\" 2222 2223",
    }
  } else {
      exec { 'Configure OAM Interface':
        command => "sm-configure interface controller oam-interface \"\" ${oam_my_unit_ip} 2222 2223 ${oam_peer_unit_ip} 2222 2223",
      }
    exec { 'Configure Management Interface':
      command => "sm-configure interface controller management-interface ${mgmt_ip_multicast} ${management_my_unit_ip} 2222 2223 ${management_peer_unit_ip} 2222 2223",
    }
  }

  exec { 'Configure OAM IP':
    command => "sm-configure service_instance oam-ip oam-ip \"ip=${oam_ip_param_ip},cidr_netmask=${oam_ip_param_mask},nic=${oam_ip_interface},arp_count=7\"",
  }


  if $system_mode == 'duplex-direct' or $system_mode == 'simplex' {
      exec { 'Configure Management IP':
        command => "sm-configure service_instance management-ip management-ip \"ip=${mgmt_ip_param_ip},cidr_netmask=${mgmt_ip_param_mask},nic=${mgmt_ip_interface},arp_count=7,dc=yes\"",
      }
  } else {
      exec { 'Configure Management IP':
        command => "sm-configure service_instance management-ip management-ip \"ip=${mgmt_ip_param_ip},cidr_netmask=${mgmt_ip_param_mask},nic=${mgmt_ip_interface},arp_count=7\"",
      }
  }

  # Create the PXEBoot IP service if it is configured
  if str2bool($::is_initial_config) {
      exec { 'Configure PXEBoot IP service in SM (service-group-member pxeboot-ip)':
          command => "sm-provision service-group-member controller-services pxeboot-ip",
      } ->
      exec { 'Configure PXEBoot IP service in SM (service pxeboot-ip)':
          command => "sm-provision service pxeboot-ip",
      }
  }

  if $system_mode == 'duplex-direct' or $system_mode == 'simplex' {
      exec { 'Configure PXEBoot IP':
          command => "sm-configure service_instance pxeboot-ip pxeboot-ip \"ip=${pxeboot_ip_param_ip},cidr_netmask=${pxeboot_ip_param_mask},nic=${pxeboot_ip_interface},arp_count=7,dc=yes\"",
      }
  } else {
      exec { 'Configure PXEBoot IP':
          command => "sm-configure service_instance pxeboot-ip pxeboot-ip \"ip=${pxeboot_ip_param_ip},cidr_netmask=${pxeboot_ip_param_mask},nic=${pxeboot_ip_interface},arp_count=7\"",
      }
  }

  exec { 'Configure Postgres DRBD':
    command => "sm-configure service_instance drbd-pg drbd-pg:${hostunit} \"drbd_resource=${pg_drbd_resource}\"",
  }

  exec { 'Configure Postgres FileSystem':
    command => "sm-configure service_instance pg-fs pg-fs \"rmon_rsc_name=database-storage,device=${pg_fs_device},directory=${pg_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
  }

  exec { 'Configure Postgres':
    command => "sm-configure service_instance postgres postgres \"pgctl=/usr/bin/pg_ctl,pgdata=${pg_data_dir}\"",
  }

  exec { 'Configure Rabbit DRBD':
    command => "sm-configure service_instance drbd-rabbit drbd-rabbit:${hostunit} \"drbd_resource=${rabbit_drbd_resource}\"",
  }

  exec { 'Configure Rabbit FileSystem':
    command => "sm-configure service_instance rabbit-fs rabbit-fs \"rmon_rsc_name=messaging-storage,device=${rabbit_fs_device},directory=${rabbit_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
  }

  exec { 'Configure Rabbit':
    command => "sm-configure service_instance rabbit rabbit \"server=${rabbitmq_server},ctl=${rabbitmqctl},pid_file=${rabbit_pid},nodename=${rabbit_node_name},mnesia_base=${rabbit_mnesia_base},ip=${mgmt_ip_param_ip}\"",
  }

  if $kubernetes_enabled {
    exec { 'Provision Docker Distribution FS in SM (service-group-member dockerdistribution-fs)':
      command => "sm-provision service-group-member controller-services dockerdistribution-fs",
    } ->
    exec { 'Provision Docker Distribution FS in SM (service dockerdistribution-fs)':
      command => "sm-provision service dockerdistribution-fs",
    } ->
    exec { 'Provision Docker Distribution DRBD in SM (service-group-member drbd-dockerdistribution)':
      command => "sm-provision service-group-member controller-services drbd-dockerdistribution",
    } ->
    exec { 'Provision Docker Distribution DRBD in SM (service drbd-dockerdistribution)':
      command => "sm-provision service drbd-dockerdistribution",
    } ->
    exec { 'Configure Docker Distribution DRBD':
      command => "sm-configure service_instance drbd-dockerdistribution drbd-dockerdistribution:${hostunit} \"drbd_resource=${dockerdistribution_drbd_resource}\"",
    }->
    exec { 'Configure Docker Distribution FileSystem':
      command => "sm-configure service_instance dockerdistribution-fs dockerdistribution-fs \"device=${dockerdistribution_fs_device},directory=${dockerdistribution_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
    }
  } else {
    exec { 'Deprovision Docker Distribution FS in SM (service-group-member dockerdistribution-fs)':
      command => "sm-deprovision service-group-member controller-services dockerdistribution-fs",
    } ->
    exec { 'Deprovision Docker Distribution FS in SM (service dockerdistribution-fs)':
      command => "sm-deprovision service dockerdistribution-fs",
    } ->
    exec { 'Deprovision Docker Distribution DRBD in SM (service-group-member drbd-dockerdistribution)':
      command => "sm-deprovision service-group-member controller-services drbd-dockerdistribution",
    } ->
    exec { 'Deprovision Docker Distribution DRBD in SM (service drbd-dockerdistribution)':
      command => "sm-deprovision service drbd-dockerdistribution",
    }
  }

  exec { 'Configure CGCS DRBD':
    command => "sm-configure service_instance drbd-cgcs drbd-cgcs:${hostunit} drbd_resource=${cgcs_drbd_resource}",
  }

  exec { 'Configure CGCS FileSystem':
    command => "sm-configure service_instance cgcs-fs cgcs-fs \"rmon_rsc_name=cloud-storage,device=${cgcs_fs_device},directory=${cgcs_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
  }

  exec { 'Configure CGCS Export FileSystem':
    command => "sm-configure service_instance cgcs-export-fs cgcs-export-fs \"fsid=1,directory=${cgcs_fs_directory},options=rw,sync,no_root_squash,no_subtree_check,clientspec=${cgcs_nfs_subnet_url},unlock_on_stop=true\"",
  }

  exec { 'Configure Extension DRBD':
    command => "sm-configure service_instance drbd-extension drbd-extension:${hostunit} \"drbd_resource=${extension_drbd_resource}\"",
  }

  exec { 'Configure Extension FileSystem':
    command => "sm-configure service_instance extension-fs extension-fs \"rmon_rsc_name=extension-storage,device=${extension_fs_device},directory=${extension_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
  }

  exec { 'Configure Extension Export FileSystem':
    command => "sm-configure service_instance extension-export-fs extension-export-fs \"fsid=1,directory=${extension_fs_directory},options=rw,sync,no_root_squash,no_subtree_check,clientspec=${platform_nfs_subnet_url},unlock_on_stop=true\"",
  }

  if $drbd_patch_enabled {
    exec { 'Configure Patch-vault DRBD':
      command => "sm-configure service_instance drbd-patch-vault drbd-patch-vault:${hostunit} \"drbd_resource=${patch_drbd_resource}\"",
    }

    exec { 'Configure Patch-vault FileSystem':
      command => "sm-configure service_instance patch-vault-fs patch-vault-fs \"rmon_rsc_name=patch-vault-storage,device=${patch_fs_device},directory=${patch_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
    }
  }

  if $kubernetes_enabled {
    exec { 'Configure ETCD DRBD':
      command => "sm-configure service_instance drbd-etcd drbd-etcd:${hostunit} drbd_resource=${etcd_drbd_resource}",
    }

    exec { 'Configure ETCD DRBD FileSystem':
      command => "sm-configure service_instance etcd-fs etcd-fs \"device=${etcd_fs_device},directory=${etcd_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
    }    
  }

  if $system_mode == 'duplex-direct' or $system_mode == 'simplex' {
      exec { 'Configure CGCS NFS':
        command => "sm-configure service_instance cgcs-nfs-ip cgcs-nfs-ip \"ip=${cgcs_nfs_ip_param_ip},cidr_netmask=${cgcs_nfs_ip_param_mask},nic=${cgcs_nfs_ip_interface},arp_count=7,dc=yes\"",
      }
  } else {
      exec { 'Configure CGCS NFS':
        command => "sm-configure service_instance cgcs-nfs-ip cgcs-nfs-ip \"ip=${cgcs_nfs_ip_param_ip},cidr_netmask=${cgcs_nfs_ip_param_mask},nic=${cgcs_nfs_ip_interface},arp_count=7\"",
      }
  }

  if $region_config {
      # In a default Multi-Region configuration, Keystone is running as a
      # shared service in the Primary Region so need to deprovision that
      # service in all non-Primary Regions. 
      # However in the case of Distributed Cloud Multi-Region configuration,
      # each Subcloud is running its own Keystone
      if $::platform::params::distributed_cloud_role =='subcloud' {
        $configure_keystone = true

        # Deprovision Horizon when running as a subcloud
        exec { 'Deprovision OpenStack - Horizon (service-group-member)':
          command => "sm-deprovision service-group-member web-services horizon",
        } ->
        exec { 'Deprovision OpenStack - Horizon (service)':
          command => "sm-deprovision service horizon",
        }

      } else {
        exec { 'Deprovision OpenStack - Keystone (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services keystone",
        } ->
        exec { 'Deprovision OpenStack - Keystone (service)':
          command => "sm-deprovision service keystone",
        }
        $configure_keystone = false
      }

      if $glance_region_name != $region_2_name {
        $configure_glance = false

        exec { 'Deprovision OpenStack - Glance Registry (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services glance-registry",
        } ->
        exec { 'Deprovision OpenStack - Glance Registry (service)':
          command => "sm-deprovision service glance-registry",
        } ->
        exec { 'Deprovision OpenStack - Glance API (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services glance-api",
        } ->
        exec { 'Deprovision OpenStack - Glance API (service)':
          command => "sm-deprovision service glance-api",
        }
      } else {
        $configure_glance = true
        if $glance_cached {
           exec { 'Deprovision OpenStack - Glance Registry (service-group-member)':
             command => "sm-deprovision service-group-member cloud-services glance-registry",
           } ->
           exec { 'Deprovision OpenStack - Glance Registry (service)':
             command => "sm-deprovision service glance-registry",
           }
         }
      }
  } elsif $kubernetes_enabled {
      $configure_keystone = true
      $configure_glance = false
  } else {
      $configure_keystone = true
      $configure_glance = true
  }

  if $configure_keystone {
    exec { 'Configure OpenStack - Keystone':
        command => "sm-configure service_instance keystone keystone \"config=/etc/keystone/keystone.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},os_auth_url=${os_auth_url}, \"",
    }
  }

  if $configure_glance {
      if !$glance_cached {
        exec { 'Configure OpenStack - Glance Registry':
          command => "sm-configure service_instance glance-registry glance-registry \"config=/etc/glance/glance-registry.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},keystone_get_token_url=${os_auth_url}/tokens\"",
        } ->
        exec { 'Provision OpenStack - Glance Registry (service-group-member)':
          command => "sm-provision service-group-member cloud-services glance-registry",
        } ->
        exec { 'Provision OpenStack - Glance Registry (service)':
          command => "sm-provision service glance-registry",
        }
      }

      exec { 'Configure OpenStack - Glance API':
        command => "sm-configure service_instance glance-api glance-api \"config=/etc/glance/glance-api.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},os_auth_url=${os_auth_url}\"",
      } ->
      exec { 'Provision OpenStack - Glance API (service-group-member)':
        command => "sm-provision service-group-member cloud-services glance-api",
      } ->
      exec { 'Provision OpenStack - Glance API (service)':
        command => "sm-provision service glance-api",
      }
  } else {
      # Deprovision Glance API and Glance Registry incase of a kubernetes config
      exec { 'Deprovision OpenStack - Glance Registry (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services glance-registry",
      } ->
      exec { 'Deprovision OpenStack - Glance Registry(service)':
          command => "sm-deprovision service glance-registry",
      }

      exec { 'Deprovision OpenStack - Glance API (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services glance-api",
      } ->
      exec { 'Deprovision OpenStack - Glance API(service)':
          command => "sm-deprovision service glance-api",
      }
  }

  if $cinder_service_enabled {
      exec { 'Configure OpenStack - Cinder API':
        command => "sm-configure service_instance cinder-api cinder-api \"config=/etc/cinder/cinder.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},keystone_get_token_url=${os_auth_url}/tokens\"",
      } ->
      exec { 'Provision OpenStack - Cinder API (service-group-member)':
        command => "sm-provision service-group-member cloud-services cinder-api",
      } ->
      exec { 'Provision OpenStack - Cinder API (service)':
        command => "sm-provision service cinder-api",
      }

      exec { 'Configure OpenStack - Cinder Scheduler':
        command => "sm-configure service_instance cinder-scheduler cinder-scheduler \"config=/etc/cinder/cinder.conf,user=root,amqp_server_port=${amqp_server_port}\"",
      } ->
      exec { 'Provision OpenStack - Cinder Scheduler (service-group-member)':
        command => "sm-provision service-group-member cloud-services cinder-scheduler",
      } ->
      exec { 'Provision OpenStack - Cinder Scheduler (service)':
        command => "sm-provision service cinder-scheduler",
      }

      exec { 'Configure OpenStack - Cinder Volume':
        command => "sm-configure service_instance cinder-volume cinder-volume \"config=/etc/cinder/cinder.conf,user=root,amqp_server_port=${amqp_server_port},multibackend=true\"",
      } ->
      exec { 'Provision OpenStack - Cinder Volume (service-group-member)':
        command => "sm-provision service-group-member cloud-services cinder-volume",
      } ->
      exec { 'Configure Cinder Volume in SM':
        command => "sm-provision service cinder-volume",
      }

      exec { 'Configure OpenStack - Cinder Backup':
        command => "sm-configure service_instance cinder-backup cinder-backup \"config=/etc/cinder/cinder.conf,user=root,amqp_server_port=${amqp_server_port}\"",
      } ->
      exec { 'Provision OpenStack - Cinder Backup (service-group-member)':
        command => "sm-provision service-group-member cloud-services cinder-backup",
      } ->
      exec { 'Provision OpenStack - Cinder Backup (service)':
        command => "sm-provision service cinder-backup",
      }

      if 'lvm' in $cinder_backends {
          # Cinder DRBD
          exec { 'Configure Cinder LVM in SM (service-group-member drbd-cinder)':
            command => "sm-provision service-group-member controller-services drbd-cinder",
          } ->
          exec { 'Configure Cinder LVM in SM (service drbd-cinder)':
            command => "sm-provision service drbd-cinder",
          } ->

          # Cinder LVM
          exec { 'Configure Cinder LVM in SM (service-group-member cinder-lvm)':
            command => "sm-provision service-group-member controller-services cinder-lvm",
          } ->
          exec { 'Configure Cinder LVM in SM (service cinder-lvm)':
            command => "sm-provision service cinder-lvm",
          } ->

          # TGTd
          exec { 'Configure Cinder LVM in SM (service-group-member iscsi)':
            command => "sm-provision service-group-member controller-services iscsi",
          } ->
          exec { 'Configure Cinder LVM in SM (service iscsi)':
            command => "sm-provision service iscsi",
          } ->

          exec { 'Configure Cinder DRBD service instance':
            command => "sm-configure service_instance drbd-cinder drbd-cinder:${hostunit} drbd_resource=${cinder_drbd_resource}",
          }
          exec { 'Configure Cinder LVM service instance':
            command => "sm-configure service_instance cinder-lvm cinder-lvm \"rmon_rsc_name=volume-storage,volgrpname=${cinder_vg_name}\"",
          }
          exec { 'Configure iscsi service instance':
            command => "sm-configure service_instance iscsi iscsi \"\"",
          }
      

          # Cinder IP
          exec { 'Configure Cinder LVM in SM (service-group-member cinder-ip)':
            command => "sm-provision service-group-member controller-services cinder-ip",
          } ->
          exec { 'Configure Cinder LVM in SM (service cinder-ip)':
            command => "sm-provision service cinder-ip",
          }

          if $system_mode == 'duplex-direct' or $system_mode == 'simplex' {
            exec { 'Configure Cinder IP service instance':
                command => "sm-configure service_instance cinder-ip cinder-ip \"ip=${cinder_ip_param_ip},cidr_netmask=${cinder_ip_param_mask},nic=${cinder_ip_interface},arp_count=7,dc=yes\"",
            }
          } else {
            exec { 'Configure Cinder IP service instance':
                command => "sm-configure service_instance cinder-ip cinder-ip \"ip=${cinder_ip_param_ip},cidr_netmask=${cinder_ip_param_mask},nic=${cinder_ip_interface},arp_count=7\"",
            }
        }
    }
  } else {
      exec { 'Deprovision OpenStack - Cinder API (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services cinder-api",
      } ->
      exec { 'Deprovision OpenStack - Cinder API (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service cinder-api",
      } ->
      exec { 'Deprovision OpenStack - Cinder Scheduler (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services cinder-scheduler",
      } ->
      exec { 'Deprovision OpenStack - Cinder Scheduler (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service cinder-scheduler",
      } ->
      exec { 'Deprovision OpenStack - Cinder Volume (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services cinder-volume",
      } ->
      exec { 'Deprovision OpenStack - Cinder Volume (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service cinder-volume",
      } ->
      exec { 'Deprovision OpenStack - Cinder Backup (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services cinder-backup",
      } ->
      exec { 'Deprovision OpenStack - Cinder Backup (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service cinder-backup",
      }
  }

  if $region_config {
      if $neutron_region_name != $region_2_name {
          $configure_neturon = false

          exec { 'Deprovision OpenStack - Neutron Server (service-group-member)':
            command => "sm-deprovision service-group-member cloud-services neutron-server",
          } ->
          exec { 'Deprovision OpenStack - Neutron Server (service)':
            command => "sm-deprovision service neutron-server",
          }
      } else {
          $configure_neturon = true
      }
  } elsif $kubernetes_enabled {
      $configure_neturon = false
  } else {
      $configure_neturon = true
  }

  if $configure_neturon {
      exec { 'Configure OpenStack - Neutron Server':
        command => "sm-configure service_instance neutron-server neutron-server \"config=/etc/neutron/neutron.conf,plugin_config=${neutron_plugin_config},sriov_plugin_config=${neutron_sriov_plugin_config},user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},keystone_get_token_url=${os_auth_url}/tokens\"",
      }
  }

  if $kubernetes_enabled != true {

    exec { 'Configure OpenStack - Nova API':
      command => "sm-configure service_instance nova-api nova-api \"config=/etc/nova/nova.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},keystone_get_token_url=${os_auth_url}/tokens\"",
    }

    exec { 'Configure OpenStack - Nova Placement API':
      command => "sm-configure service_instance nova-placement-api nova-placement-api \"config=/etc/nova/nova.conf,user=root,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},keystone_get_token_url=${os_auth_url}/tokens,host=${mgmt_ip_param_ip}\"",
    }

    exec { 'Configure OpenStack - Nova Scheduler':
      command => "sm-configure service_instance nova-scheduler nova-scheduler \"config=/etc/nova/nova.conf,database_server_port=${db_server_port},amqp_server_port=${amqp_server_port}\"",
    }

    exec { 'Configure OpenStack - Nova Conductor':
      command => "sm-configure service_instance nova-conductor nova-conductor \"config=/etc/nova/nova.conf,database_server_port=${db_server_port},amqp_server_port=${amqp_server_port}\"",
    }

    exec { 'Configure OpenStack - Nova Console Authorization':
      command => "sm-configure service_instance nova-console-auth nova-console-auth \"config=/etc/nova/nova.conf,user=root,database_server_port=${db_server_port},amqp_server_port=${amqp_server_port}\"",
    }

    exec { 'Configure OpenStack - Nova NoVNC':
      command => "sm-configure service_instance nova-novnc nova-novnc \"config=/etc/nova/nova.conf,user=root,console_port=${novnc_console_port}\"",
    }

    exec { 'Configure OpenStack - Ceilometer Agent Notification':
      command => "sm-configure service_instance ceilometer-agent-notification ceilometer-agent-notification \"config=/etc/ceilometer/ceilometer.conf\"",
    }
  } else {
      # Deprovision Openstack services if Kubernetes Config is enabled

      # Deprovision Nova Services
      exec { 'Deprovision OpenStack - Nova API (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-api",
      } ->
      exec { 'Deprovision OpenStack - Nova API(service)':
          command => "sm-deprovision service nova-api",
      }

      exec { 'Deprovision OpenStack - Nova API Proxy (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-api-proxy",
      } ->
      exec { 'Deprovision OpenStack - Nova API Proxy(service)':
          command => "sm-deprovision service nova-api-proxy",
      }

      exec { 'Deprovision OpenStack - Nova Placement API (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-placement-api",
      } ->
      exec { 'Deprovision OpenStack - Nova Placement API(service)':
          command => "sm-deprovision service nova-placement-api",
      }

      exec { 'Deprovision OpenStack - Nova Scheduler (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-scheduler",
      } ->
      exec { 'Deprovision OpenStack - Nova Scheduler(service)':
          command => "sm-deprovision service nova-scheduler",
      }

      exec { 'Deprovision OpenStack - Nova Conductor (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-conductor",
      } ->
      exec { 'Deprovision OpenStack - Nova Conductor(service)':
          command => "sm-deprovision service nova-conductor",
      }

      exec { 'Deprovision OpenStack - Nova Console Auth (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-console-auth",
      } ->
      exec { 'Deprovision OpenStack - Nova Console Auth(service)':
          command => "sm-deprovision service nova-console-auth",
      }

      exec { 'Deprovision OpenStack - Nova NoVNC (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services nova-novnc",
      } ->
      exec { 'Deprovision OpenStack - Nova NoVNC(service)':
          command => "sm-deprovision service nova-novnc",
      }

      # Deprovision Celiometer
      exec { 'Deprovision OpenStack - Ceilometer Agent Notification (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services ceilometer-agent-notification",
      } ->
      exec { 'Deprovision OpenStack - Ceilometer Agent Notification(service)':
          command => "sm-deprovision service ceilometer-agent-notification",
      }

      # Deprovision Neutron Server
      exec { 'Deprovision OpenStack - Neutron Server (service-group-member)':
          command => "sm-deprovision service-group-member cloud-services neutron-server",
      } ->
      exec { 'Deprovision OpenStack - Neutron Server (service)':
          command => "sm-deprovision service neutron-server",
      }

      # Deprovision Horizon
      exec { 'Deprovision OpenStack - Horizon (service-group-member)':
          command => "sm-deprovision service-group-member web-services horizon",
      } ->
      exec { 'Deprovision OpenStack - Horizon(service)':
          command => "sm-deprovision service horizon",
      }
  }

  if $heat_service_enabled {
    exec { 'Configure OpenStack - Heat Engine':
      command => "sm-configure service_instance heat-engine heat-engine \"config=/etc/heat/heat.conf,user=root,database_server_port=${db_server_port},amqp_server_port=${amqp_server_port}\"",
    }

    exec { 'Configure OpenStack - Heat API':
      command => "sm-configure service_instance heat-api heat-api \"config=/etc/heat/heat.conf,user=root,server_port=${heat_api_port}\"",
    }

    exec { 'Configure OpenStack - Heat API CFN':
      command => "sm-configure service_instance heat-api-cfn heat-api-cfn \"config=/etc/heat/heat.conf,user=root,server_port=${heat_api_cfn_port}\"",
    }

    exec { 'Configure OpenStack - Heat API CloudWatch':
      command => "sm-configure service_instance heat-api-cloudwatch heat-api-cloudwatch \"config=/etc/heat/heat.conf,user=root,server_port=${heat_api_cloudwatch_port}\"",
    }
  } else {
      exec { 'Deprovision OpenStack - Heat Engine (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services heat-engine",
      } ->
      exec { 'Deprovision OpenStack - Heat Engine(service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service heat-engine",
      }

      exec { 'Deprovision OpenStack - Heat API (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services heat-api",
      } ->
      exec { 'Deprovision OpenStack - Heat API (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service heat-api",
      }

      exec { 'Deprovision OpenStack - Heat API CFN (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services heat-api-cfn",
      } ->
      exec { 'Deprovision OpenStack - Heat API CFN (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service heat-api-cfn",
      }

      exec { 'Deprovision OpenStack - Heat API CloudWatch (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services heat-api-cloudwatch",
      } ->
      exec { 'Deprovision OpenStack - Heat API CloudWatch (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service heat-api-cloudwatch",
      }
  }

  # Gnocchi
  if $gnocchi_enabled {

    exec { 'Configure OpenStack - Gnocchi API':
      command => "sm-configure service_instance gnocchi-api gnocchi-api \"config=/etc/gnocchi/gnocchi.conf\"",
    }

    exec { 'Configure OpenStack - Gnocchi metricd':
      command => "sm-configure service_instance gnocchi-metricd gnocchi-metricd \"config=/etc/gnocchi/gnocchi.conf\"",
    }
  } else {
      exec { 'Deprovision OpenStack - Gnocchi API (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services gnocchi-api",
      } ->
      exec { 'Deprovision OpenStack - Gnocchi API (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service gnocchi-api",
      }

      exec { 'Deprovision OpenStack - Gnocchi metricd (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services gnocchi-metricd",
      } ->
      exec { 'Deprovision OpenStack - Gnocchi metricd (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service gnocchi-metricd",
      }
  }

  # AODH
  if $aodh_enabled {

    exec { 'Configure OpenStack - AODH API':
      command => "sm-configure service_instance aodh-api aodh-api \"config=/etc/aodh/aodh.conf\"",
    }

    exec { 'Configure OpenStack - AODH Evaluator':
      command => "sm-configure service_instance aodh-evaluator aodh-evaluator \"config=/etc/aodh/aodh.conf\"",
    }

    exec { 'Configure OpenStack - AODH Listener':
      command => "sm-configure service_instance aodh-listener aodh-listener \"config=/etc/aodh/aodh.conf\"",
    }

    exec { 'Configure OpenStack - AODH Notifier':
      command => "sm-configure service_instance aodh-notifier aodh-notifier \"config=/etc/aodh/aodh.conf\"",
    }
  } else {
      exec { 'Deprovision OpenStack - AODH API (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services aodh-api",
      } ->
      exec { 'Deprovision OpenStack - AODH API (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service aodh-api",
      }

      exec { 'Deprovision OpenStack - AODH Evaluator (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services aodh-evaluator",
      } ->
      exec { 'Deprovision OpenStack - AODH Evaluator (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service aodh-evaluator",
      }

      exec { 'Deprovision OpenStack - AODH Listener (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services aodh-listener",
      } ->
      exec { 'Deprovision OpenStack - AODH Listener (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service aodh-listener",
      }

      exec { 'Deprovision OpenStack - AODH Notifier (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services aodh-notifier",
      } ->
      exec { 'Deprovision OpenStack - AODH Notifier (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service aodh-notifier",
      }
  }

  # Panko
  if $panko_enabled {
    exec { 'Configure OpenStack - Panko API':
      command => "sm-configure service_instance panko-api panko-api \"config=/etc/panko/panko.conf\"",
    }
  } else {
      exec { 'Deprovision OpenStack - Panko API (service-group-member)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service-group-member cloud-services panko-api",
      } ->
      exec { 'Deprovision OpenStack - Panko API (service)':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "sm-deprovision service panko-api",
      }
  }

  # Murano
  exec { 'Configure OpenStack - Murano API':
    command => "sm-configure service_instance murano-api murano-api \"config=/etc/murano/murano.conf\"",
  }

  exec { 'Configure OpenStack - Murano Engine':
    command => "sm-configure service_instance murano-engine murano-engine \"config=/etc/murano/murano.conf\"",
  }

  # Magnum
  exec { 'Configure OpenStack - Magnum API':
    command => "sm-configure service_instance magnum-api magnum-api \"config=/etc/magnum/magnum.conf\"",
  }

  exec { 'Configure OpenStack - Magnum Conductor':
    command => "sm-configure service_instance magnum-conductor magnum-conductor \"config=/etc/magnum/magnum.conf\"",
  }

  # Ironic
  exec { 'Configure OpenStack - Ironic API':
    command => "sm-configure service_instance ironic-api ironic-api \"config=/etc/ironic/ironic.conf\"",
  }

  exec { 'Configure OpenStack - Ironic Conductor':
    command => "sm-configure service_instance ironic-conductor ironic-conductor \"config=/etc/ironic/ironic.conf,tftproot=${ironic_tftproot}\"",
  }

  exec { 'Configure OpenStack - Nova Compute':
    command => "sm-configure service_instance nova-compute nova-compute \"config=/etc/nova/nova-ironic.conf\"",
  }

  exec { 'Configure OpenStack - Nova Serialproxy':
    command => "sm-configure service_instance nova-serialproxy nova-serialproxy \"config=/etc/nova/nova-ironic.conf\"",
  }

  #exec { 'Configure Power Management Conductor':
  #  command => "sm-configure service_instance power-mgmt-conductor power-mgmt-conductor \"config=/etc/power_mgmt/power-mgmt-conductor.ini\"",
  #}

  #exec { 'Configure Power Management API':
  #  command => "sm-configure service_instance power-mgmt-api power-mgmt-api \"config=/etc/power_mgmt/power-mgmt-api.ini\"",
  #}

  exec { 'Configure NFS Management':
    command => "sm-configure service_instance nfs-mgmt nfs-mgmt \"exports=${nfs_server_mgmt_exports},mounts=${nfs_server_mgmt_mounts}\"",
  }

  exec { 'Configure Platform DRBD':
    command => "sm-configure service_instance drbd-platform drbd-platform:${hostunit} \"drbd_resource=${platform_drbd_resource}\"",
  }

  exec { 'Configure Platform FileSystem':
    command => "sm-configure service_instance platform-fs platform-fs \"rmon_rsc_name=platform-storage,device=${platform_fs_device},directory=${platform_fs_directory},options=noatime,nodiratime,fstype=ext4,check_level=20\"",
  }

  exec { 'Configure Platform Export FileSystem':
    command => "sm-configure service_instance platform-export-fs platform-export-fs \"fsid=0,directory=${platform_fs_directory},options=rw,sync,no_root_squash,no_subtree_check,clientspec=${platform_nfs_subnet_url},unlock_on_stop=true\"",
  }

  # etcd
  exec { 'Configure ETCD':
    command => "sm-configure service_instance etcd etcd \"config=/etc/etcd/etcd.conf,user=root\"",
  }

  # Docker Distribution
  exec { 'Configure Docker Distribution':
    command => "sm-configure service_instance docker-distribution docker-distribution \"\"",
  }

  if $system_mode == 'duplex-direct' or $system_mode == 'simplex' {
      exec { 'Configure Platform NFS':
        command => "sm-configure service_instance platform-nfs-ip platform-nfs-ip \"ip=${platform_nfs_ip_param_ip},cidr_netmask=${platform_nfs_ip_param_mask},nic=${mgmt_ip_interface},arp_count=7,dc=yes\"",
      }
  } else {
      exec { 'Configure Platform NFS':
        command => "sm-configure service_instance platform-nfs-ip platform-nfs-ip \"ip=${platform_nfs_ip_param_ip},cidr_netmask=${platform_nfs_ip_param_mask},nic=${mgmt_ip_interface},arp_count=7\"",
      }
  }

  exec { 'Configure System Inventory API':
    command => "sm-configure service_instance sysinv-inv sysinv-inv \"dbg=false,os_username=${os_username},os_project_name=${os_project_name},os_user_domain_name=${os_user_domain_name},os_project_domain_name=${os_project_domain_name},os_auth_url=${os_auth_url},os_region_name=${os_region_name},system_url=${system_url}\"",
  }

  exec { 'Configure System Inventory Conductor':
    command => "sm-configure service_instance sysinv-conductor sysinv-conductor \"dbg=false\"",
  }

  exec { 'Configure Maintenance Agent':
    command => "sm-configure service_instance mtc-agent mtc-agent \"state=active,logging=true,mode=normal,dbg=false\"",
  }

  exec { 'Configure Heartbeat Service Agent':
    command => "sm-configure service_instance hbs-agent hbs-agent \"state=active,logging=true,dbg=false\"",
  }

  exec { 'Configure DNS Mask':
    command => "sm-configure service_instance dnsmasq dnsmasq \"\"",
  }

  exec { 'Configure Fault Manager':
    command => "sm-configure service_instance fm-mgr fm-mgr \"\"",
  }

  exec { 'Configure Open LDAP':
    command => "sm-configure service_instance open-ldap open-ldap \"\"",
  }

  if $infra_ip_interface {
    exec { 'Configure Infrastructure Interface':
      command => "sm-configure interface controller infrastructure-interface ${infra_ip_multicast} ${infra_my_unit_ip} 2222 2223 ${infra_peer_unit_ip} 2222 2223",
    }
  }

  if $system_mode == 'duplex-direct' or $system_mode == 'duplex' {
      exec { 'Configure System Mode':
      command => "sm-configure system --cpe_mode ${system_mode}",
    }

  }

  if $system_mode == 'simplex' {
    exec { 'Configure oam-service redundancy model':
      command => "sm-configure service_group yes controller oam-services N 1 0 \"\" directory-services",
    }

    exec { 'Configure controller-services redundancy model':
      command => "sm-configure service_group yes controller controller-services N 1 0 \"\" directory-services",
    }

    exec { 'Configure cloud-services redundancy model':
      command => "sm-configure service_group yes controller cloud-services N 1 0 \"\" directory-services",
    }

    exec { 'Configure vim-services redundancy model':
      command => "sm-configure service_group yes controller vim-services N 1 0 \"\" directory-services",
    }

    exec { 'Configure patching-services redundancy model':
      command => "sm-configure service_group yes controller patching-services N 1 0 \"\" \"\"",
    }

    exec { 'Configure directory-services redundancy model':
      command => "sm-configure service_group yes controller directory-services N 1 0 \"\" \"\"",
    }

    exec { 'Configure web-services redundancy model':
      command => "sm-configure service_group yes controller web-services N 1 0 \"\" \"\"",
    }

  }

  exec { 'Provision extension-fs (service-group-member)':
    command => "sm-provision service-group-member controller-services  extension-fs",
  } ->
  exec { 'Provision extension-fs (service)':
    command => "sm-provision service extension-fs",
  } ->
  exec { 'Provision drbd-extension (service-group-member)':
    command => "sm-provision service-group-member controller-services drbd-extension",
  } ->
  exec { 'Provision drbd-extension (service)':
    command => "sm-provision service drbd-extension",
  } ->
  exec { 'Provision extension-export-fs  (service-group-member)':
    command => "sm-provision service-group-member controller-services extension-export-fs",
  } ->
  exec { 'Provision extension-export-fs (service)':
    command => "sm-provision service extension-export-fs",
  }

  if $drbd_patch_enabled {
    exec { 'Provision patch-vault-fs (service-group-member)':
      command => "sm-provision service-group-member controller-services  patch-vault-fs",
    } ->
    exec { 'Provision patch-vault-fs (service)':
      command => "sm-provision service patch-vault-fs",
    } ->
    exec { 'Provision drbd-patch-vault (service-group-member)':
      command => "sm-provision service-group-member controller-services drbd-patch-vault",
    } ->
    exec { 'Provision drbd-patch-vault (service)':
      command => "sm-provision service drbd-patch-vault",
    }
  }
  
  # Configure ETCD for Kubernetes
  if $kubernetes_enabled {
    exec { 'Provision etcd-fs (service-group-member)':
      command => "sm-provision service-group-member controller-services etcd-fs",
    } ->
    exec { 'Provision etcd-fs (service)':
      command => "sm-provision service etcd-fs",
    } ->
    exec { 'Provision drbd-etcd (service-group-member)':
      command => "sm-provision service-group-member controller-services drbd-etcd",
    } ->
    exec { 'Provision drbd-etcd (service)':
      command => "sm-provision service drbd-etcd",
    } ->
    exec { 'Provision ETCD (service-group-member)': 
        command => "sm-provision service-group-member controller-services etcd",
    } ->
    exec { 'Provision ETCD (service)':
      command => "sm-provision service etcd",
    } 
  }
  else {
    exec { 'Deprovision ETCD (service-group-member)':
      command => "sm-deprovision service-group-member controller-services etcd",
    } ->
    exec { 'Deprovision ETCD (service)':
      command => "sm-deprovision service etcd",
    }
  }

  # Configure Docker Distribution
  if $kubernetes_enabled {
    exec { 'Provision Docker Distribution (service-group-member)':
        command => "sm-provision service-group-member controller-services docker-distribution",
    } ->
    exec { 'Provision Docker Distribution (service)':
      command => "sm-provision service docker-distribution",
    }
  }

  exec { 'Configure Murano Rabbit':
    command => "sm-configure service_instance murano-rabbit murano-rabbit \"server=${rabbitmq_server},ctl=${rabbitmqctl},nodename=${murano_rabbit_node_name},mnesia_base=${murano_rabbit_mnesia_base},ip=${oam_ip_param_ip},config_file=${murano_rabbit_config_file},env_config_file=${murano_rabbit_env_config_file},pid_file=${murano_rabbit_pid},dist_port=${murano_rabbit_dist_port}\"",
  }

  # optionally bring up/down Murano and murano agent's rabbitmq
  if $disable_murano_agent {
    exec { 'Deprovision Murano Rabbitmq (service-group-member)':
      command => "sm-deprovision service-group-member controller-services murano-rabbit",
    } ->
    exec { 'Deprovision Murano Rabbitmq (service)':
      command => "sm-deprovision service murano-rabbit",
    }
  } else {
    exec { 'Provision Murano Rabbitmq (service-group-member)':
      command => "sm-provision service-group-member controller-services murano-rabbit",
    } ->
    exec { 'Provision Murano Rabbitmq (service)':
      command => "sm-provision service murano-rabbit",
    }
  }

  if $murano_configured {
    exec { 'Provision OpenStack - Murano API (service-group-member)':
      command => "sm-provision service-group-member cloud-services murano-api",
    } ->
    exec { 'Provision OpenStack - Murano API (service)':
      command => "sm-provision service murano-api",
    } ->
    exec { 'Provision OpenStack - Murano Engine (service-group-member)':
      command => "sm-provision service-group-member cloud-services murano-engine",
    } ->
    exec { 'Provision OpenStack - Murano Engine (service)':
      command => "sm-provision service murano-engine",
    }
  } else {
    exec { 'Deprovision OpenStack - Murano API (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services murano-api",
    } ->
    exec { 'Deprovision OpenStack - Murano API (service)':
      command => "sm-deprovision service murano-api",
    } ->
    exec { 'Deprovision OpenStack - Murano Engine (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services murano-engine",
    } ->
    exec { 'Deprovision OpenStack - Murano Engine (service)':
      command => "sm-deprovision service murano-engine",
    }
  }

  # optionally bring up/down Magnum
  if $magnum_configured {
    exec { 'Provision OpenStack - Magnum API (service-group-member)':
      command => "sm-provision service-group-member cloud-services magnum-api",
    } ->
    exec { 'Provision OpenStack - Magnum API (service)':
      command => "sm-provision service magnum-api",
    } ->
    exec { 'Provision OpenStack - Magnum Conductor (service-group-member)':
      command => "sm-provision service-group-member cloud-services magnum-conductor",
    } ->
    exec { 'Provision OpenStack - Magnum Conductor (service)':
      command => "sm-provision service magnum-conductor",
    }
  } else {
    exec { 'Deprovision OpenStack - Magnum API (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services magnum-api",
    } ->
    exec { 'Deprovision OpenStack - Magnum API (service)':
      command => "sm-deprovision service magnum-api",
    } ->
    exec { 'Deprovision OpenStack - Magnum Conductor (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services magnum-conductor",
    } ->
    exec { 'Deprovision OpenStack - Magnum Conductor (service)':
      command => "sm-deprovision service magnum-conductor",
    }
  }

  # optionally bring up/down Ironic
  if $ironic_configured {
    exec { 'Provision OpenStack - Ironic API (service-group-member)':
      command => "sm-provision service-group-member cloud-services ironic-api",
    } ->
    exec { 'Provision OpenStack - Ironic API (service)':
      command => "sm-provision service ironic-api",
    } ->
    exec { 'Provision OpenStack - Ironic Conductor (service-group-member)':
      command => "sm-provision service-group-member cloud-services ironic-conductor",
    } ->
    exec { 'Provision OpenStack - Ironic Conductor (service)':
      command => "sm-provision service ironic-conductor",
    } ->
    exec { 'Provision OpenStack - Nova Compute (service-group-member)':
      command => "sm-provision service-group-member cloud-services nova-compute",
    } ->
    exec { 'Provision OpenStack - Nova Compute (service)':
      command => "sm-provision service nova-compute",
    } ->
    exec { 'Provision OpenStack - Nova Serialproxy (service-group-member)':
      command => "sm-provision service-group-member cloud-services nova-serialproxy",
    } ->
    exec { 'Provision OpenStack - Nova Serialproxy (service)':
      command => "sm-provision service nova-serialproxy",
    }
    if $ironic_tftp_ip != undef {
      case $::hostname {
        $controller_0_hostname: {
          exec { 'Configure Ironic TFTP IP service instance':
            command => "sm-configure service_instance ironic-tftp-ip ironic-tftp-ip \"ip=${ironic_tftp_ip},cidr_netmask=${ironic_netmask},nic=${ironic_controller_0_nic},arp_count=7\"",
          }
        }
        $controller_1_hostname: {
          exec { 'Configure Ironic TFTP IP service instance':
            command => "sm-configure service_instance ironic-tftp-ip ironic-tftp-ip \"ip=${ironic_tftp_ip},cidr_netmask=${ironic_netmask},nic=${ironic_controller_1_nic},arp_count=7\"",
          }
        }
        default: {
        }
      }

      exec { 'Provision Ironic TFTP Floating IP (service-group-member)':
        command => "sm-provision service-group-member controller-services ironic-tftp-ip",
      } ->
      exec { 'Provision Ironic TFTP Floating IP (service)':
        command => "sm-provision service ironic-tftp-ip",
      }
    }
  } else {
    exec { 'Deprovision OpenStack - Ironic API (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services ironic-api",
    } ->
    exec { 'Deprovision OpenStack - Ironic API (service)':
      command => "sm-deprovision service ironic-api",
    } ->
    exec { 'Deprovision OpenStack - Ironic Conductor (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services ironic-conductor",
    } ->
    exec { 'Deprovision OpenStack - Ironic Conductor (service)':
      command => "sm-deprovision service ironic-conductor",
    } ->
    exec { 'Deprovision OpenStack - Nova Compute (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services nova-compute",
    } ->
    exec { 'Deprovision OpenStack - Nova Compute (service)':
      command => "sm-deprovision service nova-compute",
    } ->
    exec { 'Deprovision OpenStack - Nova Serialproxy (service-group-member)':
      command => "sm-deprovision service-group-member cloud-services nova-serialproxy",
    } ->
    exec { 'Deprovision OpenStack - Nova Serialproxy (service)':
      command => "sm-deprovision service nova-serialproxy",
    } ->
    exec { 'Provision Ironic TFTP Floating IP (service-group-member)':
      command => "sm-deprovision service-group-member controller-services ironic-tftp-ip",
    } ->
    exec { 'Provision Ironic TFTP Floating IP (service)':
      command => "sm-deprovision service ironic-tftp-ip",
    }
  }

  if $ceph_configured {
    # Ceph-Rest-API
    exec { 'Provision Ceph-Rest-Api (service-domain-member storage-services)':
      command => "sm-provision service-domain-member controller storage-services",
    } ->
    exec { 'Provision Ceph-Rest-Api (service-group storage-services)':
      command => "sm-provision service-group storage-services",
    } ->
    exec { 'Provision Ceph-Rest-Api (service-group-member ceph-rest-api)':
      command => "sm-provision service-group-member storage-services ceph-rest-api",
    } ->
    exec { 'Provision Ceph-Rest-Api (service ceph-rest-api)':
      command => "sm-provision service ceph-rest-api",
    } ->

    # Ceph-Manager
    exec { 'Provision Ceph-Manager (service-domain-member storage-monitoring-services)':
       command => "sm-provision service-domain-member controller storage-monitoring-services",
    } ->
    exec { 'Provision Ceph-Manager service-group storage-monitoring-services)':
       command => "sm-provision service-group storage-monitoring-services",
    } ->
    exec { 'Provision Ceph-Manager (service-group-member ceph-manager)':
       command => "sm-provision service-group-member storage-monitoring-services ceph-manager",
    } ->
    exec { 'Provision Ceph-Manager in SM (service ceph-manager)':
       command => "sm-provision service ceph-manager",
    }
  }

  # Ceph-Rados-Gateway
  if $rgw_configured {
    exec {'Provision Ceph-Rados-Gateway (service-group-member ceph-radosgw)':
      command => "sm-provision service-group-member storage-monitoring-services ceph-radosgw"
    } ->
    exec { 'Provision Ceph-Rados-Gateway (service ceph-radosgw)':
      command => "sm-provision service ceph-radosgw",
    }
  }

 if $ldapserver_remote {
   # if remote LDAP server is configured, deprovision local openldap service.
   exec { 'Deprovision open-ldap service group member':
     command => "/usr/bin/sm-deprovision service-group-member directory-services open-ldap",
   } ->
   exec { 'Deprovision open-ldap service':
     command => "/usr/bin/sm-deprovision service open-ldap",
   }
 }

  if $::platform::params::distributed_cloud_role =='systemcontroller' {
    exec { 'Provision distributed-cloud-services (service-domain-member distributed-cloud-services)':
      command => "sm-provision service-domain-member controller distributed-cloud-services",
    } ->
    exec { 'Provision distributed-cloud-services (service-group distributed-cloud-services)':
      command => "sm-provision service-group distributed-cloud-services",
    } ->
    exec { 'Provision DCManager-Manager (service-group-member dcmanager-manager)':
         command => "sm-provision service-group-member distributed-cloud-services dcmanager-manager",
    } ->
    exec { 'Provision DCManager-Manager in SM (service dcmanager-manager)':
         command => "sm-provision service dcmanager-manager",
    } ->
    exec { 'Provision DCManager-RestApi (service-group-member dcmanager-api)':
         command => "sm-provision service-group-member distributed-cloud-services dcmanager-api",
    } ->
    exec { 'Provision DCManager-RestApi in SM (service dcmanager-api)':
         command => "sm-provision service dcmanager-api",
    } ->
    exec { 'Provision DCOrch-Engine (service-group-member dcorch-engine)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-engine",
    } ->
    exec { 'Provision DCOrch-Engine in SM (service dcorch-engine)':
       command => "sm-provision service dcorch-engine",
    } ->
    exec { 'Provision DCOrch-Snmp (service-group-member dcorch-snmp)':
        command => "sm-provision service-group-member distributed-cloud-services dcorch-snmp",
    } ->
    exec { 'Provision DCOrch-Snmp in SM (service dcorch-snmp)':
       command => "sm-provision service dcorch-snmp",
    } ->
    exec { 'Provision DCOrch-Identity-Api-Proxy (service-group-member dcorch-identity-api-proxy)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-identity-api-proxy",
    } ->
    exec { 'Provision DCOrch-Identity-Api-Proxy in SM (service dcorch-identity-api-proxy)':
       command => "sm-provision service dcorch-identity-api-proxy",
    } ->
    exec { 'Provision DCOrch-Sysinv-Api-Proxy (service-group-member dcorch-sysinv-api-proxy)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-sysinv-api-proxy",
    } ->
    exec { 'Provision DCOrch-Sysinv-Api-Proxy in SM (service dcorch-sysinv-api-proxy)':
       command => "sm-provision service dcorch-sysinv-api-proxy",
    } ->
    exec { 'Provision DCOrch-Nova-Api-Proxy (service-group-member dcorch-nova-api-proxy)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-nova-api-proxy",
    } ->
    exec { 'Provision DCOrch-Nova-Api-Proxy in SM (service dcorch-nova-api-proxy)':
       command => "sm-provision service dcorch-nova-api-proxy",
    } ->
    exec { 'Provision DCOrch-Neutron-Api-Proxy (service-group-member dcorch-neutron-api-proxy)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-neutron-api-proxy",
    } ->
    exec { 'Provision DCOrch-Neutron-Api-Proxy in SM (service dcorch-neutron-api-proxy)':
       command => "sm-provision service dcorch-neutron-api-proxy",
    } ->
    exec { 'Provision DCOrch-Patch-Api-Proxy (service-group-member dcorch-patch-api-proxy)':
       command => "sm-provision service-group-member distributed-cloud-services dcorch-patch-api-proxy",
    } ->
    exec { 'Provision DCOrch-Patch-Api-Proxy in SM (service dcorch-patch-api-proxy)':
       command => "sm-provision service dcorch-patch-api-proxy",
    } ->
    exec { 'Configure Platform - DCManager-Manager':
      command => "sm-configure service_instance dcmanager-manager dcmanager-manager \"\"",
    } ->
    exec { 'Configure OpenStack - DCManager-API':
      command => "sm-configure service_instance dcmanager-api dcmanager-api \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-Engine':
      command => "sm-configure service_instance dcorch-engine dcorch-engine \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-Snmp':
      command => "sm-configure service_instance dcorch-snmp dcorch-snmp \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-identity-api-proxy':
      command => "sm-configure service_instance dcorch-identity-api-proxy dcorch-identity-api-proxy \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-sysinv-api-proxy':
      command => "sm-configure service_instance dcorch-sysinv-api-proxy dcorch-sysinv-api-proxy \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-nova-api-proxy':
      command => "sm-configure service_instance dcorch-nova-api-proxy dcorch-nova-api-proxy \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-neutron-api-proxy':
      command => "sm-configure service_instance dcorch-neutron-api-proxy dcorch-neutron-api-proxy \"\"",
    } ->
    exec { 'Configure OpenStack - DCOrch-patch-api-proxy':
      command => "sm-configure service_instance dcorch-patch-api-proxy dcorch-patch-api-proxy \"\"",
    }
    if $cinder_service_enabled {
      notice("Enable cinder-api-proxy")
      exec { 'Provision DCOrch-Cinder-Api-Proxy (service-group-member dcorch-cinder-api-proxy)':
           command => "sm-provision service-group-member distributed-cloud-services dcorch-cinder-api-proxy",
      } ->
      exec { 'Provision DCOrch-Cinder-Api-Proxy in SM (service dcorch-cinder-api-proxy)':
        command => "sm-provision service dcorch-cinder-api-proxy",
      } ->
      exec { 'Configure OpenStack - DCOrch-cinder-api-proxy':
        command => "sm-configure service_instance dcorch-cinder-api-proxy dcorch-cinder-api-proxy \"\"",
      }
    }
  }  
}


define platform::sm::restart {
  exec {"sm-restart-${name}":
    command => "sm-restart-safe service ${name}",
  }
}


# WARNING:
# This should only be invoked in a standalone / simplex mode.
# It is currently used during infrastructure network post-install apply
# to ensure SM reloads the updated configuration after the manifests
# are applied.
# Semantic checks enforce the standalone condition (all hosts locked)
class platform::sm::reload {

  # Ensure service(s) are restarted before SM is restarted
  Platform::Sm::Restart <| |> -> Class[$name]

  exec { 'pmon-stop-sm':
    command => 'pmon-stop sm'
  } ->
  file { '/var/run/sm/sm.db':
    ensure => absent
  } ->
  exec { 'pmon-start-sm':
    command => 'pmon-start sm'
  }
}


class platform::sm::norestart::runtime {
  include ::platform::sm
}

class platform::sm::runtime {
  include ::platform::sm

  class { 'platform::sm::reload':
    stage => post,
  }
}
