class platform::compute::params (
  $compute_cpu_list = '',
  $platform_cpu_list = '',
  $reserved_vswitch_cores = '',
  $reserved_platform_cores = '',
  $compute_base_reserved = '',
  $compute_vswitch_reserved = '',
) { }

class platform::compute::config
  inherits ::platform::compute::params {

  file { "/etc/nova/compute_reserved.conf":
      ensure => 'present',
      replace => true,
      content => template('platform/compute_reserved.conf.erb')
  }
}

class platform::compute::grub::params (
  $n_cpus = '',
  $cpu_options = '',
  $m_hugepages = 'hugepagesz=2M hugepages=0',
  $default_pgsz = 'default_hugepagesz=2M',
  $keys = ['kvm-intel.eptad', 'default_hugepagesz', 'hugepagesz', 'hugepages', 'isolcpus', 'nohz_full', 'rcu_nocbs', 'kthread_cpus', 'irqaffinity'],
) {

  if $::is_broadwell_processor {
    $eptad = 'kvm-intel.eptad=0'
  } else {
    $eptad = ''
  }

  if $::is_gb_page_supported {
    $gb_hugepages = "hugepagesz=1G hugepages=$::number_of_numa_nodes"
  } else {
    $gb_hugepages = ''
  }

  $grub_updates = strip("${eptad} ${$gb_hugepages} ${m_hugepages} ${default_pgsz} ${cpu_options}")
}

class platform::compute::grub::update
  inherits ::platform::compute::grub::params {

  notice("Updating grub configuration")

  $to_be_removed = join($keys, " ")
  exec { "Remove the cpu arguments":
    command => "grubby --update-kernel=ALL --remove-args='$to_be_removed'",
  } ->
  exec { "Add the cpu arguments":
    command => "grubby --update-kernel=ALL --args='$grub_updates'",
  }
}

class platform::compute::grub::recovery {

  notice("Update Grub and Reboot")

  class {'platform::compute::grub::update': } -> Exec['reboot-recovery']

  exec { "reboot-recovery":
    command => "reboot",
  }
}

class platform::compute::grub::audit
  inherits ::platform::compute::grub::params {

  if ! str2bool($::is_initial_config_primary) {

    notice("Audit CPU and Grub Configuration")

    $expected_n_cpus = $::number_of_logical_cpus
    $n_cpus_ok = ("$n_cpus" == "$expected_n_cpus")

    $cmd_ok = check_grub_config($grub_updates)

    if $cmd_ok and $n_cpus_ok {
      $ensure = present
      notice("CPU and Boot Argument audit passed.")
    } else {
      $ensure = absent
      if !$cmd_ok {
        notice("Kernel Boot Argument Mismatch")
        include ::platform::compute::grub::recovery
      }
    }

    file { "/var/run/compute_huge_goenabled":
      ensure  => $ensure,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
    }
  }
}

class platform::compute::grub::runtime {
  include ::platform::compute::grub::update
}

# Mounts virtual hugetlbfs filesystems for each supported page size
class platform::compute::hugetlbf {

  if str2bool($::is_hugetlbfs_enabled) {

    $fs_list = generate("/bin/bash", "-c", "ls -1d /sys/kernel/mm/hugepages/hugepages-*")
    $array = split($fs_list, '\n')
    $array.each | String $val | {
      $page_name = generate("/bin/bash", "-c", "basename $val")
      $page_size = strip(regsubst($page_name, 'hugepages-', ''))
      $hugemnt ="/mnt/huge-$page_size"
      $options = "pagesize=${page_size}"

      notice("Mounting hugetlbfs at: $hugemnt")
      exec { "create $hugemnt":
        command => "mkdir -p ${hugemnt}",
        onlyif  => "test ! -d ${hugemnt}",
      } ->
      mount { "${hugemnt}":
        name     => "${hugemnt}",
        device   => 'none',
        fstype   => 'hugetlbfs',
        ensure   => 'mounted',
        options  => "${options}",
        atboot   => 'yes',
        remounts => true,
      }
    }
  }
}

class platform::compute::hugepage::params (
  $nr_hugepages_2M = undef,
  $nr_hugepages_1G = undef,
  $vswitch_2M_pages = '',
  $vswitch_1G_pages = '',
  $vm_4K_pages = '',
  $vm_2M_pages = '',
  $vm_1G_pages = '',
) {}


define allocate_pages (
  $path,
  $page_count,
) {
  exec { "Allocate ${page_count} ${path}":
    command => "echo $page_count > $path",
    onlyif => "test -f $path",
  }
}

# Allocates HugeTLB memory according to the attributes specified in the
# nr_hugepages_2M and nr_hugepages_1G
class platform::compute::allocate
  inherits ::platform::compute::hugepage::params {

  # determine the node file system
  if str2bool($::is_per_numa_supported) {
    $nodefs = '/sys/devices/system/node'
  } else {
    $nodefs = '/sys/kernel/mm'
  }

  if $nr_hugepages_2M != undef {
    $nr_hugepages_2M_array = regsubst($nr_hugepages_2M, '[\(\)\"]', '', 'G').split(' ')
    $nr_hugepages_2M_array.each | String $val | {
      $per_node_2M = $val.split(':')
      if size($per_node_2M)== 3 {
        $node = $per_node_2M[0]
        $page_size = $per_node_2M[1]
        allocate_pages { "Start ${node} ${page_size}":
          path => "${nodefs}/${node}/hugepages/hugepages-${page_size}/nr_hugepages",
          page_count => $per_node_2M[2],
        }
      }
    }
  }

  if $nr_hugepages_1G  != undef {
    $nr_hugepages_1G_array = regsubst($nr_hugepages_1G , '[\(\)\"]', '', 'G').split(' ')
    $nr_hugepages_1G_array.each | String $val | {
      $per_node_1G = $val.split(':')
      if size($per_node_1G)== 3 {
        $node = $per_node_1G[0]
        $page_size = $per_node_1G[1]
        allocate_pages { "Start ${node} ${page_size}":
          path => "${nodefs}/${node}/hugepages/hugepages-${page_size}/nr_hugepages",
          page_count => $per_node_1G[2],
        }
      }
    }
  }
}

class platform::compute::extend
  inherits ::platform::compute::hugepage::params {

  # nova-compute reads on init, extended nova compute options
  # used with nova accounting
  file { "/etc/nova/compute_extend.conf":
      ensure => 'present',
      replace => true,
      content => template('platform/compute_extend.conf.erb')
  }
}

# Mount resctrl to allow Cache Allocation Technology per VM
class platform::compute::resctrl {

  if str2bool($::is_resctrl_supported) {
    mount { "/sys/fs/resctrl":
      name     => '/sys/fs/resctrl',
      device   => 'resctrl',
      fstype   => 'resctrl',
      ensure   => 'mounted',
      atboot   => 'yes',
      remounts => true,
    }
  }
}

# Set Power Management QoS resume latency constraints for CPUs.
# The PM QoS resume latency limit is set to shallow C-state for vswitch CPUs.
# All other CPUs are allowed to go to the deepest C-state available.
class platform::compute::pmqos (
  $low_wakeup_cpus = '',
  $hight_wakeup_cpus = '',
) {

  if str2bool($::is_compute_subfunction) and str2bool($::is_lowlatency_subfunction) {

    $script = "/usr/bin/set-cpu-wakeup-latency.sh"

    # Set low wakeup latency (shallow C-state) for vswitch CPUs using PM QoS interface
    exec { "low-wakeup-latency":
      command => "${script} low ${low_wakeup_cpus}",
      onlyif => "test -f ${script}",
      logoutput => true,
    }

    #Set high wakeup latency (deep C-state) for non-vswitch CPUs using PM QoS interface
    exec { "high-wakeup-latency":
      command => "${script} high ${hight_wakeup_cpus}",
      onlyif => "test -f ${script}",
      logoutput => true,
    }
  }
}

class platform::compute {

  Class[$name] -> Class['::platform::vswitch']
  Class[$name] -> Class['::nova::compute']

  require ::platform::compute::grub::audit
  require ::platform::compute::hugetlbf
  require ::platform::compute::allocate
  require ::platform::compute::pmqos
  require ::platform::compute::resctrl
  require ::platform::compute::extend
  require ::platform::compute::config
}
