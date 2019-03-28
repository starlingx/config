class platform::compute::params (
  $worker_cpu_list = '',
  $platform_cpu_list = '',
  $reserved_vswitch_cores = '',
  $reserved_platform_cores = '',
  $worker_base_reserved = '',
  $compute_vswitch_reserved = '',
) { }

class platform::compute::config
  inherits ::platform::compute::params {

  file { '/etc/platform/worker_reserved.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/worker_reserved.conf.erb')
  }

  file { '/etc/systemd/system.conf.d/platform-cpuaffinity.conf':
      ensure  => 'present',
      replace => true,
      content => template('platform/systemd-system-cpuaffinity.conf.erb')
  }
}

class platform::compute::config::runtime {
  include ::platform::compute::config
}

class platform::compute::grub::params (
  $n_cpus = '',
  $cpu_options = '',
  $m_hugepages = 'hugepagesz=2M hugepages=0',
  $g_hugepages = undef,
  $default_pgsz = 'default_hugepagesz=2M',
  $keys = [
    'kvm-intel.eptad',
    'default_hugepagesz',
    'hugepagesz',
    'hugepages',
    'isolcpus',
    'nohz_full',
    'rcu_nocbs',
    'kthread_cpus',
    'irqaffinity',
  ],
) {

  if $::is_broadwell_processor {
    $eptad = 'kvm-intel.eptad=0'
  } else {
    $eptad = ''
  }

  if $::is_gb_page_supported {
    if $g_hugepages != undef {
      $gb_hugepages = $g_hugepages
    } else {
      $gb_hugepages = "hugepagesz=1G hugepages=${::number_of_numa_nodes}"
    }
  } else {
    $gb_hugepages = ''
  }

  $grub_updates = strip("${eptad} ${$gb_hugepages} ${m_hugepages} ${default_pgsz} ${cpu_options}")
}

class platform::compute::grub::update
  inherits ::platform::compute::grub::params {

  notice('Updating grub configuration')

  $to_be_removed = join($keys, ' ')
  exec { 'Remove the cpu arguments':
    command => "grubby --update-kernel=ALL --remove-args='${to_be_removed}'",
  }
  -> exec { 'Add the cpu arguments':
    command => "grubby --update-kernel=ALL --args='${grub_updates}'",
  }
}

class platform::compute::grub::recovery {

  notice('Update Grub and Reboot')

  class {'platform::compute::grub::update': } -> Exec['reboot-recovery']

  exec { 'reboot-recovery':
    command => 'reboot',
  }
}

class platform::compute::grub::audit
  inherits ::platform::compute::grub::params {

  if ! str2bool($::is_initial_config_primary) {

    notice('Audit CPU and Grub Configuration')

    $expected_n_cpus = Integer($::number_of_logical_cpus)
    $n_cpus_ok = ($n_cpus == $expected_n_cpus)

    $cmd_ok = check_grub_config($grub_updates)

    if $cmd_ok and $n_cpus_ok {
      $ensure = present
      notice('CPU and Boot Argument audit passed.')
    } else {
      $ensure = absent
      if !$cmd_ok {
        notice('Kernel Boot Argument Mismatch')
        include ::platform::compute::grub::recovery
      } else {
        notice("Mismatched CPUs: Found=${n_cpus}, Expected=${expected_n_cpus}")
      }
    }

    file { '/var/run/worker_goenabled':
      ensure => $ensure,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
  }
}

class platform::compute::grub::runtime {
  include ::platform::compute::grub::update
}

# Mounts virtual hugetlbfs filesystems for each supported page size
class platform::compute::hugetlbf {

  if str2bool($::is_hugetlbfs_enabled) {

    $fs_list = generate('/bin/bash', '-c', 'ls -1d /sys/kernel/mm/hugepages/hugepages-*')
    $array = split($fs_list, '\n')
    $array.each | String $val | {
      $page_name = generate('/bin/bash', '-c', "basename ${val}")
      $page_size = strip(regsubst($page_name, 'hugepages-', ''))
      $hugemnt ="/mnt/huge-${page_size}"
      $options = "pagesize=${page_size}"

      # TODO: Once all the code is switched over to use the /dev
      # mount point  we can get rid of this mount point.
      notice("Mounting hugetlbfs at: ${hugemnt}")
      exec { "create ${hugemnt}":
        command => "mkdir -p ${hugemnt}",
        onlyif  => "test ! -d ${hugemnt}",
      }
      -> mount { $hugemnt:
        ensure   => 'mounted',
        device   => 'none',
        fstype   => 'hugetlbfs',
        name     => $hugemnt,
        options  => $options,
        atboot   => 'yes',
        remounts => true,
      }

      # The libvirt helm chart expects hugepages to be mounted
      # under /dev so let's do that.
      $hugemnt2 ="/dev/huge-${page_size}"
      notice("Mounting hugetlbfs at: ${hugemnt2}")
      file { $hugemnt2:
        ensure => 'directory',
        owner  => 'root',
        group  => 'root',
        mode   => '0755',
      }
      -> mount { $hugemnt2:
        ensure   => 'mounted',
        device   => 'none',
        fstype   => 'hugetlbfs',
        name     => $hugemnt2,
        options  => $options,
        atboot   => 'yes',
        remounts => true,
      }
    }

    # The libvirt helm chart also assumes that the default hugepage size
    # will be mounted at /dev/hugepages so let's make that happen too.
    # Once we upstream a fix to the helm chart to automatically determine
    # the mountpoint then we can remove this.
    $page_size = '2M'
    $hugemnt ='/dev/hugepages'
    $options = "pagesize=${page_size}"

    notice("Mounting hugetlbfs at: ${hugemnt}")
    exec { "create ${hugemnt}":
      command => "mkdir -p ${hugemnt}",
      onlyif  => "test ! -d ${hugemnt}",
    }
    -> mount { $hugemnt:
      ensure   => 'mounted',
      device   => 'none',
      fstype   => 'hugetlbfs',
      name     => $hugemnt,
      options  => $options,
      atboot   => 'yes',
      remounts => true,
    }
  }
}

# lint:ignore:variable_is_lowercase
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
    command => "echo ${page_count} > ${path}",
    onlyif  => "test -f ${path}",
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
          path       => "${nodefs}/${node}/hugepages/hugepages-${page_size}/nr_hugepages",
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
          path       => "${nodefs}/${node}/hugepages/hugepages-${page_size}/nr_hugepages",
          page_count => $per_node_1G[2],
        }
      }
    }
  }
}
# lint:endignore:variable_is_lowercase

# Mount resctrl to allow Cache Allocation Technology per VM
class platform::compute::resctrl {

  if str2bool($::is_resctrl_supported) {
    mount { '/sys/fs/resctrl':
      ensure   => 'mounted',
      device   => 'resctrl',
      fstype   => 'resctrl',
      name     => '/sys/fs/resctrl',
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

  if str2bool($::is_worker_subfunction) and str2bool($::is_lowlatency_subfunction) {

    $script = '/usr/bin/set-cpu-wakeup-latency.sh'

    if $low_wakeup_cpus != '""' {
      # Set low wakeup latency (shallow C-state) for vswitch CPUs using PM QoS interface
      exec { 'low-wakeup-latency':
        command   => "${script} low ${low_wakeup_cpus}",
        onlyif    => "test -f ${script}",
        logoutput => true,
      }
    }

    if $hight_wakeup_cpus != '""' {
      #Set high wakeup latency (deep C-state) for non-vswitch CPUs using PM QoS interface
      exec { 'high-wakeup-latency':
        command   => "${script} high ${hight_wakeup_cpus}",
        onlyif    => "test -f ${script}",
        logoutput => true,
      }
    }
  }
}

# Set systemd machine.slice cgroup cpuset to be used with VMs,
# and configure this cpuset to span all logical cpus and numa nodes.
# NOTES:
# - The parent directory cpuset spans all online cpus and numa nodes.
# - Setting the machine.slice cpuset prevents this from inheriting
#   kubernetes libvirt pod's cpuset, since machine.slice cgroup will be
#   created when a VM is launched if it does not already exist.
# - systemd automatically mounts cgroups and controllers, so don't need
#   to do that here.
class platform::compute::machine {
  $parent_dir = '/sys/fs/cgroup/cpuset'
  $parent_mems = "${parent_dir}/cpuset.mems"
  $parent_cpus = "${parent_dir}/cpuset.cpus"
  $machine_dir = "${parent_dir}/machine.slice"
  $machine_mems = "${machine_dir}/cpuset.mems"
  $machine_cpus = "${machine_dir}/cpuset.cpus"
  notice("Create ${machine_dir}")
  file { $machine_dir :
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }
  -> exec { "Create ${machine_mems}" :
    command => "/bin/cat ${parent_mems} > ${machine_mems}",
  }
  -> exec { "Create ${machine_cpus}" :
    command => "/bin/cat ${parent_cpus} > ${machine_cpus}",
  }
}

class platform::compute {

  Class[$name] -> Class['::platform::vswitch']

  require ::platform::compute::grub::audit
  require ::platform::compute::hugetlbf
  require ::platform::compute::allocate
  require ::platform::compute::pmqos
  require ::platform::compute::resctrl
  require ::platform::compute::machine
  require ::platform::compute::config
}
