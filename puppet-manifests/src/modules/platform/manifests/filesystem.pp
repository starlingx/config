class platform::filesystem::params (
  $vg_name = 'cgts-vg',
) {}


define platform::filesystem (
  $lv_name,
  $lv_size,
  $mountpoint,
  $fs_type,
  $fs_options,
  $fs_use_all = false,
  $mode = '0750',
) {
  include ::platform::filesystem::params
  $vg_name = $::platform::filesystem::params::vg_name

  $device = "/dev/${vg_name}/${lv_name}"

  if !$fs_use_all {
    $size = "${lv_size}G"
    $fs_size_is_minsize = true
  }
  else {
    # use all available space
    $size = undef
    $fs_size_is_minsize = false
  }

  # create logical volume
  logical_volume { $lv_name:
      ensure          => present,
      volume_group    => $vg_name,
      size            => $size,
      size_is_minsize => $fs_size_is_minsize,
  }

  # create filesystem
  -> filesystem { $device:
    ensure  => present,
    fs_type => $fs_type,
    options => $fs_options,
  }

  -> file { $mountpoint:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => $mode,
  }

  -> mount { $name:
    ensure  => 'mounted',
    atboot  => 'yes',
    name    => $mountpoint,
    device  => $device,
    options => 'defaults',
    fstype  => $fs_type,
  }

  # The above mount resource doesn't actually remount devices that were already present in /etc/fstab, but were
  # unmounted during manifest application. To get around this, we attempt to mount them again, if they are not
  # already mounted.
  -> exec { "mount ${device}":
    unless  => "mount | awk '{print \$3}' | grep -Fxq ${mountpoint}",
    command => "mount ${mountpoint}",
    path    => '/usr/bin'
  }
}


define platform::filesystem::resize(
  $lv_name,
  $lv_size,
  $devmapper,
) {
  include ::platform::filesystem::params
  $vg_name = $::platform::filesystem::params::vg_name

  $device = "/dev/${vg_name}/${lv_name}"

  # TODO (rchurch): Fix this... Allowing return code 5 so that lvextends using the same size doesn't blow up
  exec { "lvextend ${device}":
    command => "lvextend -L${lv_size}G ${device}",
    returns => [0, 5]
  }
  # After a partition extend, make sure that there is no leftover drbd
  # type metadata from a previous install. Drbd writes its meta at the
  # very end of a block device causing confusion for blkid.
  -> exec { "wipe end of device ${device}":
    command => "dd if=/dev/zero of=${device} bs=512 seek=$(($(blockdev --getsz ${device}) - 34)) count=34",
    onlyif  => "blkid ${device} | grep TYPE=\\\"drbd\\\"",
  }
  -> exec { "resize2fs ${devmapper}":
    command => "resize2fs ${devmapper}",
    onlyif  => "blkid -s TYPE -o value ${devmapper} | grep -v xfs",
  }
  -> exec { "xfs_growfs ${devmapper}":
    command => "xfs_growfs ${devmapper}",
    onlyif  => "blkid -s TYPE -o value ${devmapper} | grep xfs",
  }
}


class platform::filesystem::backup::params (
  $lv_name = 'backup-lv',
  $lv_size = '5',
  $mountpoint = '/opt/backups',
  $devmapper = '/dev/mapper/cgts--vg-backup--lv',
  $fs_type = 'ext4',
  $fs_options = ' '
) {}

class platform::filesystem::backup
  inherits ::platform::filesystem::backup::params {

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
    fs_type    => $fs_type,
    fs_options => $fs_options
  }
}

class platform::filesystem::scratch::params (
  $lv_size = '8',
  $lv_name = 'scratch-lv',
  $mountpoint = '/scratch',
  $devmapper = '/dev/mapper/cgts--vg-scratch--lv',
  $fs_type = 'ext4',
  $fs_options = ' '
) { }

class platform::filesystem::scratch
  inherits ::platform::filesystem::scratch::params {

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
    fs_type    => $fs_type,
    fs_options => $fs_options
  }
}


class platform::filesystem::docker::params (
  $lv_size = '1',
  $lv_name = 'docker-lv',
  $mountpoint = '/var/lib/docker',
  $devmapper = '/dev/mapper/cgts--vg-docker--lv',
  $fs_type = 'xfs',
  $fs_options = '-n ftype=1',
  $fs_use_all = false
) { }

class platform::filesystem::docker
  inherits ::platform::filesystem::docker::params {

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
    fs_type    => $fs_type,
    fs_options => $fs_options,
    fs_use_all => $fs_use_all,
    mode       => '0711',
  }
}


class platform::filesystem::storage {

  class {'platform::filesystem::docker::params' :
    lv_size => 30
  }
  -> class {'platform::filesystem::docker' :
  }

  Class['::platform::lvm::vg::cgts_vg'] -> Class['::platform::filesystem::docker']
}


class platform::filesystem::compute {

  class {'platform::filesystem::docker::params' :
    lv_size => 30
  }
  -> class {'platform::filesystem::docker' :
  }

  Class['::platform::lvm::vg::cgts_vg'] -> Class['::platform::filesystem::docker']
}

class platform::filesystem::controller {
  include ::platform::filesystem::backup
  include ::platform::filesystem::scratch
  include ::platform::filesystem::docker
}


class platform::filesystem::backup::runtime {

  include ::platform::filesystem::backup::params
  $lv_name = $::platform::filesystem::backup::params::lv_name
  $lv_size = $::platform::filesystem::backup::params::lv_size
  $devmapper = $::platform::filesystem::backup::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name   => $lv_name,
    lv_size   => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::scratch::runtime {

  include ::platform::filesystem::scratch::params
  $lv_name = $::platform::filesystem::scratch::params::lv_name
  $lv_size = $::platform::filesystem::scratch::params::lv_size
  $devmapper = $::platform::filesystem::scratch::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name   => $lv_name,
    lv_size   => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::docker::runtime {

  include ::platform::filesystem::docker::params
  $lv_name = $::platform::filesystem::docker::params::lv_name
  $lv_size = $::platform::filesystem::docker::params::lv_size
  $devmapper = $::platform::filesystem::docker::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name   => $lv_name,
    lv_size   => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::docker::params::bootstrap (
  $lv_size = '30',
  $lv_name = 'docker-lv',
  $mountpoint = '/var/lib/docker',
  $devmapper = '/dev/mapper/cgts--vg-docker--lv',
  $fs_type = 'xfs',
  $fs_options = '-n ftype=1',
  $fs_use_all = false
) { }


class platform::filesystem::docker::bootstrap
  inherits ::platform::filesystem::docker::params::bootstrap {

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
    fs_type    => $fs_type,
    fs_options => $fs_options,
    fs_use_all => $fs_use_all,
    mode       => '0711',
  }
}
