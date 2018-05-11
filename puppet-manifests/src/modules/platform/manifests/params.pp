class platform::params (
  $config_path = undef,
  $controller_hostname,
  $controller_0_hostname = undef,
  $controller_1_hostname = undef,
  $controller_upgrade = false,
  $hostname,
  $mate_hostname = undef,
  $mate_ipaddress = undef,
  $nfs_proto = 'udp',
  $nfs_rw_size = 1024,
  $pxeboot_hostname,
  $region_1_name = undef,
  $region_2_name = undef,
  $region_config = false,
  $distributed_cloud_role = undef,
  $sdn_enabled = false,
  $software_version = undef,
  $system_mode = undef,
  $system_type = undef,
  $system_name = undef,
  $platform_cpu_count = undef,
  $vswitch_type = undef,
  $security_profile = undef,
  $security_feature = undef,
) {
  $ipv4 = 4
  $ipv6 = 6

  $nfs_mount_options = "timeo=30,proto=$nfs_proto,vers=3,rsize=$nfs_rw_size,wsize=$nfs_rw_size"

  $protected_group_name = 'wrs_protected'
  $protected_group_id = '345'

  # PUPPET 4 treats custom facts as strings. We convert to int by adding zero.
  $phys_core_count = 0 + $::physical_core_count
  $plat_res_mem = 0 + $::platform_res_mem

  # Engineering parameters common to openstack services:

  # max number of workers
  $eng_max_workers = 20
  # min number of workers
  $eng_min_workers = 1 
  # min platform core count
  $platform_default_min_cpu_count = 2
  # total system memory per worker
  $eng_worker_mb = 2000
  # memory headroom per worker (e.g., buffers, cached)
  $eng_overhead_mb = 1000

  notice("DEBUG: Platform cpu count obtained from sysinv DB is $platform_cpu_count.")

  # number of workers per service
  if $system_type == 'All-in-one' {
    $small_footprint = true

    # Set eng_workers for AIO based on the number of platform cores, not exceeding 2 for
    # AIO simplex, Xeon-D and virtual box and not exceeding 3 for AIO duplex.
    # All eng_workers derivatives are set to 1 for AIO.
    # Services can add an additional worker if it is deemed necessary in their own puppet files.
    if ($platform_cpu_count <= $platform_default_min_cpu_count) {
      $eng_workers = $platform_cpu_count
    } else {
      if $system_mode == 'simplex' or ($phys_core_count <= 8 and $plat_res_mem < 14500) or str2bool($::is_virtual) {
        $eng_workers = $platform_default_min_cpu_count
      } else {
        $eng_workers = $platform_default_min_cpu_count + 1
      }
    }
    $eng_workers_by_2 = $eng_min_workers
    $eng_workers_by_4 = $eng_min_workers
    $eng_workers_by_5 = $eng_min_workers
    $eng_workers_by_6 = $eng_min_workers
  } else {
    # number of workers we can support based on memory
    $small_footprint = false
    $eng_workers_mem = floor($::memorysize_mb) / ($eng_worker_mb + $eng_overhead_mb)
    $eng_workers = min($eng_max_workers, $eng_workers_mem, max($phys_core_count, 2))
    $eng_workers_by_2 = min($eng_max_workers, $eng_workers_mem, max($phys_core_count/2, 2))
    $eng_workers_by_4 = min($eng_max_workers, $eng_workers_mem, max($phys_core_count/4, 2))
    $eng_workers_by_5 = min($eng_max_workers, $eng_workers_mem, max($phys_core_count/5, 2))
    $eng_workers_by_6 = min($eng_max_workers, $eng_workers_mem, max($phys_core_count/6, 2))
  }

  $init_database = (str2bool($::is_initial_config_primary) or $controller_upgrade)
  $init_keystone = (str2bool($::is_initial_config_primary) or $controller_upgrade)
}
