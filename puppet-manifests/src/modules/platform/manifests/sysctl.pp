class platform::sysctl::params (
  $ip_forwarding = false,
  $ip_version = $::platform::params::ipv4,
  $low_latency = false,
) inherits ::platform::params {}


class platform::sysctl
  inherits ::platform::sysctl::params {

  # Increase min_free_kbytes to 128 MiB from 88 MiB, helps prevent OOM
  sysctl::value { 'vm.min_free_kbytes':
    value => '131072'
  }

  # Set sched_nr_migrate to standard linux default
  sysctl::value { 'kernel.sched_nr_migrate':
    value => '8',
  }

  # Tuning options for low latency compute
  if $low_latency {
    # Increase VM stat interval
    sysctl::value { 'vm.stat_interval':
      value => '10',
    }

    # Disable timer migration
    sysctl::value { 'kernel.timer_migration':
      value => '0',
    }

    # Disable RT throttling
    sysctl::value { 'kernel.sched_rt_runtime_us':
      value => '1000000',
    }
  } else {
    # Disable NUMA balancing
    sysctl::value { 'kernel.numa_balancing':
      value => '0',
    }
  }
}


class platform::sysctl::controller
  inherits ::platform::sysctl::params {

  include ::platform::sysctl

  # Engineer VM page cache tunables to prevent significant IO delays that may
  # occur if we flush a buildup of dirty pages.  Engineer VM settings to make
  # writebacks more regular. Note that Linux default proportion of page cache that
  # can be dirty is rediculously large for systems > 8GB RAM, and can result in
  # many seconds of IO wait, especially if GBs of dirty pages are written at once.
  # Note the following settings are currently only applied to controller,
  # though these are intended to be applicable to all blades. For unknown reason,
  # there was negative impact to VM traffic on computes.

  # dirty_background_bytes limits magnitude of pending IO, so
  # choose setting of 3 seconds dirty holding x 200 MB/s write speed (SSD)
  sysctl::value { 'vm.dirty_background_bytes':
    value => '600000000'
  }

  # dirty_ratio should be larger than dirty_background_bytes, set 1.3x larger
  sysctl::value { 'vm.dirty_bytes':
    value => '800000000'
  }

  # prefer reclaim of dentries and inodes, set larger than default of 100
  sysctl::value { 'vm.vfs_cache_pressure':
    value => '500'
  }

  # reduce dirty expiry to 10s from default 30s
  sysctl::value { 'vm.dirty_expire_centisecs':
    value => '1000'
  }

  # reduce dirty writeback to 1s from default 5s
  sysctl::value { 'vm.dirty_writeback_centisecs':
    value => '100'
  }

  # Setting max to 160 MB to support more connections
  # When increasing postgres connections, add 7.5 MB for every 100 connections
  sysctl::value { 'kernel.shmmax':
    value => '167772160'
  }

  if $ip_forwarding {

    if $ip_version == $::platform::params::ipv6 {
      # sysctl does not support ipv6 rp_filter
      sysctl::value { 'net.ipv6.conf.all.forwarding':
        value => '1'
      }

    } else {
      sysctl::value { 'net.ipv4.ip_forward':
        value => '1'
      }

      sysctl::value { 'net.ipv4.conf.default.rp_filter':
        value => '0'
      }

      sysctl::value { 'net.ipv4.conf.all.rp_filter':
        value => '0'
      }

      # If this manifest is applied without rebooting the controller, as is done
      # when config_controller is run, any existing interfaces will not have
      # their rp_filter setting changed. This is because the kernel uses a MAX
      # of the 'all' setting (which is now 0) and the current setting for the
      # interface (which will be 1). When a blade is rebooted, the interfaces
      # come up with the new 'default' setting so all is well.
      exec { 'Clear rp_filter for existing interfaces':
        path    => [ '/usr/bin', '/usr/sbin', '/usr/local/bin', '/etc', '/sbin', '/bin' ],
        command => "bash -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > \$f; done'",
      }
    }
  }
}


class platform::sysctl::compute {
  include ::platform::sysctl
}


class platform::sysctl::storage {
  include ::platform::sysctl
}


class platform::sysctl::controller::runtime {
  include ::platform::sysctl::controller
}
