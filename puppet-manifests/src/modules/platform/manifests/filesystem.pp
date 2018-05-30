class platform::filesystem::params (
  $fs_type = 'ext4',
  $vg_name = 'cgts-vg',
) {}


define platform::filesystem (
  $lv_name,
  $lv_size,
  $mountpoint,
) {
  include ::platform::filesystem::params
  $vg_name = $::platform::filesystem::params::vg_name

  $device = "/dev/${vg_name}/${lv_name}"

  # create logical volume
  logical_volume { $lv_name:
      ensure          => present,
      volume_group    => $vg_name,
      size            => "${lv_size}G",
      size_is_minsize => true,
  } ->

  # create filesystem
  filesystem { $device:
    ensure  => present,
    fs_type => 'ext4',
  } ->

  file { $mountpoint:
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
  } ->

  mount { $name:
    name => "$mountpoint",
    atboot => 'yes',
    ensure => 'mounted',
    device => "${device}",
    options => 'defaults',
    fstype => $::platform::filesystem::params::fs_type,
  } ->

  # The above mount resource doesn't actually remount devices that were already present in /etc/fstab, but were
  # unmounted during manifest application. To get around this, we attempt to mount them again, if they are not
  # already mounted.
  exec { "mount $device":
    unless => "mount | awk '{print \$3}' | grep -Fxq $mountpoint",
    command => "mount $mountpoint",
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
  exec { "lvextend $device":
    command => "lvextend -L${lv_size}G ${device}",
    returns => [0, 5]
  } ->
  # After a partition extend, make sure that there is no leftover drbd
  # type metadata from a previous install. Drbd writes its meta at the
  # very end of a block device causing confusion for blkid.
  exec { "wipe end of device $device":
    command => "dd if=/dev/zero of=${device} bs=512 seek=$(($(blockdev --getsz ${device}) - 34)) count=34",
    onlyif => "blkid ${device} | grep TYPE=\\\"drbd\\\"",
  } ->
  exec { "resize2fs $devmapper":
    command => "resize2fs $devmapper"
  }
}


class platform::filesystem::backup::params (
  $lv_name = 'backup-lv',
  $lv_size = '5',
  $mountpoint = '/opt/backups',
  $devmapper = '/dev/mapper/cgts--vg-backup--lv'
) {}

class platform::filesystem::backup
  inherits ::platform::filesystem::backup::params {

  platform::filesystem { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    mountpoint => $mountpoint,
  }
}


class platform::filesystem::scratch::params (
  $lv_size = '8',
  $lv_name = 'scratch-lv',
  $mountpoint = '/scratch',
  $devmapper = '/dev/mapper/cgts--vg-scratch--lv'
) { }

class platform::filesystem::scratch
  inherits ::platform::filesystem::scratch::params {

  platform::filesystem { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    mountpoint => $mountpoint,
  }
}


class platform::filesystem::img_conversions::params (
  $lv_size = '8',
  $lv_name = 'img-conversions-lv',
  $mountpoint = '/opt/img-conversions',
  $devmapper = '/dev/mapper/cgts--vg-img--conversions--lv'
) {}

class platform::filesystem::img_conversions
  inherits ::platform::filesystem::img_conversions::params {
  include ::openstack::cinder::params
  include ::openstack::glance::params

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
  }
}


class platform::filesystem::controller {
  include ::platform::filesystem::backup
  include ::platform::filesystem::scratch
  include ::platform::filesystem::img_conversions
}


class platform::filesystem::backup::runtime {

  include ::platform::filesystem::backup::params
  $lv_name = $::platform::filesystem::backup::params::lv_name
  $lv_size = $::platform::filesystem::backup::params::lv_size
  $devmapper = $::platform::filesystem::backup::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::scratch::runtime {

  include ::platform::filesystem::scratch::params
  $lv_name = $::platform::filesystem::scratch::params::lv_name
  $lv_size = $::platform::filesystem::scratch::params::lv_size
  $devmapper = $::platform::filesystem::scratch::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::img_conversions::runtime {

  include ::platform::filesystem::img_conversions::params
  include ::openstack::cinder::params
  include ::openstack::glance::params
  $lv_name = $::platform::filesystem::img_conversions::params::lv_name
  $lv_size = $::platform::filesystem::img_conversions::params::lv_size
  $devmapper = $::platform::filesystem::img_conversions::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name   => $lv_name,
    lv_size   => $lv_size,
    devmapper => $devmapper,
  }
}
