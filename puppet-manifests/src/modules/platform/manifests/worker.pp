
define platform::worker::storage::wipe_new_pv {
  $cmd = join(['/sbin/pvs --nosuffix --noheadings ',$name,' 2>/dev/null | grep nova-local || true'])
  $result = generate('/bin/sh', '-c', $cmd)
  if $result !~ /nova-local/ {
    exec { "Wipe New PV not in VG - ${name}":
      provider => shell,
      command  => "wipefs -a ${name}",
      before   => Lvm::Volume[instances_lv],
      require  => Exec['remove device mapper mapping']
    }
  }
}

define platform::worker::storage::wipe_pv_and_format {
  if $name !~ /part/ {
    exec { "Wipe removing PV ${name}":
      provider => shell,
      command  => "wipefs -a ${name}",
      require  => File_line[disable_old_lvg_disks]
    }
    -> exec { "GPT format disk PV - ${name}":
      provider => shell,
      command  => "parted -a optimal --script ${name} -- mktable gpt",
    }
  }
  else {
    exec { "Wipe removing PV ${name}":
      provider => shell,
      command  => "wipefs -a ${name}",
      require  => File_line[disable_old_lvg_disks]
    }
  }
}

class platform::worker::storage (
  $adding_pvs,
  $removing_pvs,
  $final_pvs,
  $lvm_global_filter = '[]',
  $lvm_update_filter = '[]',
  $images_rbd_pool = 'ephemeral',
  $images_rbd_ceph_conf = '/etc/ceph/ceph.conf'
) {
  $adding_pvs_str = join($adding_pvs,' ')
  $removing_pvs_str = join($removing_pvs,' ')
  $round_to_extent = false

  # Ensure partitions update prior to local storage configuration
  Class['::platform::partitions'] -> Class[$name]

  ::platform::worker::storage::wipe_new_pv { $adding_pvs: }
  ::platform::worker::storage::wipe_pv_and_format { $removing_pvs: }

  file_line { 'enable_new_lvg_disks':
      path  => '/etc/lvm/lvm.conf',
      line  => "    global_filter = ${lvm_update_filter}",
      match => '^[ ]*global_filter =',
  }
  -> exec { 'umount /var/lib/nova/instances':
    command => 'umount /var/lib/nova/instances; true',
    onlyif  => 'test -e /var/lib/nova/instances',
  }
  -> exec { 'umount /dev/nova-local/instances_lv':
    command => 'umount /dev/nova-local/instances_lv; true',
    onlyif  => 'test -e /dev/nova-local/instances_lv',
  }
  -> exec { 'remove udev leftovers':
    unless  => 'vgs nova-local',
    command => 'rm -rf /dev/nova-local || true',
  }
  -> exec { 'remove device mapper mapping':
    command => 'dmsetup remove /dev/mapper/nova--local-instances_lv || true',
    onlyif  => 'test -e /dev/mapper/nova--local-instances_lv',
  }
  -> file_line { 'disable_old_lvg_disks':
      path  => '/etc/lvm/lvm.conf',
      line  => "    global_filter = ${lvm_global_filter}",
      match => '^[ ]*global_filter =',
  }
  if ! empty($::platform::lvm::vg::nova_local::physical_volumes) {
    File_line['disable_old_lvg_disks']
    -> file { '/var/lib/nova':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
    -> exec { 'add device mapper mapping':
      command => 'lvchange -ay /dev/nova-local/instances_lv || true',
    }
    -> lvm::volume { 'instances_lv':
      ensure                    => 'present',
      vg                        => 'nova-local',
      pv                        => $final_pvs,
      size                      => 'max',
      round_to_extent           => $round_to_extent,
      allow_reduce              => true,
      nuke_fs_on_resize_failure => true,
    }
    -> filesystem { '/dev/nova-local/instances_lv':
      ensure  => present,
      fs_type => 'ext4',
      options => '-F -F',
      require => Logical_volume['instances_lv']
    }
    -> file { '/var/lib/nova/instances':
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0755',
    }
    -> exec { 'mount /dev/nova-local/instances_lv':
      unless  => 'mount | grep -q /var/lib/nova/instances',
      command => 'mount -t ext4 /dev/nova-local/instances_lv /var/lib/nova/instances',
    }
  }
}
