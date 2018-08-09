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
  } ->

  # create filesystem
  filesystem { $device:
    ensure  => present,
    fs_type => $fs_type,
    options => $fs_options,
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
    fstype => $fs_type,
  } ->

  # The above mount resource doesn't actually remount devices that were already present in /etc/fstab, but were
  # unmounted during manifest application. To get around this, we attempt to mount them again, if they are not
  # already mounted.
  exec { "mount $device":
    unless => "mount | awk '{print \$3}' | grep -Fxq $mountpoint",
    command => "mount $mountpoint",
    path => "/usr/bin"
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
  $devmapper = '/dev/mapper/cgts--vg-backup--lv',
  $fs_type = 'ext4',
  $fs_options = ' '
) {}

class platform::filesystem::backup
  inherits ::platform::filesystem::backup::params {

  platform::filesystem { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    mountpoint => $mountpoint,
    fs_type => $fs_type,
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
    lv_name => $lv_name,
    lv_size => $lv_size,
    mountpoint => $mountpoint,
    fs_type => $fs_type,
    fs_options => $fs_options
  }
}

class platform::filesystem::gnocchi::params (
  $lv_size = '5',
  $lv_name = 'gnocchi-lv',
  $mountpoint = '/opt/gnocchi',
  $devmapper = '/dev/mapper/cgts--vg-gnocchi--lv',
  $fs_type = 'ext4',
  $fs_options = '-i 8192'
) { }

class platform::filesystem::gnocchi
  inherits ::platform::filesystem::gnocchi::params {

  platform::filesystem { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    mountpoint => $mountpoint,
    fs_type => $fs_type,
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

  include ::platform::kubernetes::params

  if $::platform::kubernetes::params::enabled {
    platform::filesystem { $lv_name:
      lv_name => $lv_name,
      lv_size => $lv_size,
      mountpoint => $mountpoint,
      fs_type => $fs_type,
      fs_options => $fs_options,
      fs_use_all => $fs_use_all
    }
  }
}

class platform::filesystem::img_conversions::params (
  $lv_size = '8',
  $lv_name = 'img-conversions-lv',
  $mountpoint = '/opt/img-conversions',
  $devmapper = '/dev/mapper/cgts--vg-img--conversions--lv',
  $fs_type = 'ext4',
  $fs_options = ' '
) {}

class platform::filesystem::img_conversions
  inherits ::platform::filesystem::img_conversions::params {
  include ::openstack::cinder::params
  include ::openstack::glance::params

  platform::filesystem { $lv_name:
    lv_name    => $lv_name,
    lv_size    => $lv_size,
    mountpoint => $mountpoint,
    fs_type    => $fs_type,
    fs_options => $fs_options
  }
}


class platform::filesystem::storage {

  include ::platform::kubernetes::params

  if $::platform::kubernetes::params::enabled {
    class {'platform::filesystem::docker::params' :
      lv_size => 10
    } ->
    class {'platform::filesystem::docker' :
    }

    Class['::platform::lvm::vg::cgts_vg'] -> Class['::platform::filesystem::docker']
  }
}


class platform::filesystem::compute {

  include ::platform::kubernetes::params

  if $::platform::kubernetes::params::enabled {
    class {'platform::filesystem::docker::params' :
      fs_use_all => true
    } ->
    class {'platform::filesystem::docker' :
    }

    Class['::platform::lvm::vg::cgts_vg'] -> Class['::platform::filesystem::docker']
  }
}

class platform::filesystem::controller {
  include ::platform::filesystem::backup
  include ::platform::filesystem::scratch
  include ::platform::filesystem::docker
  include ::platform::filesystem::img_conversions
  include ::platform::filesystem::gnocchi
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


class platform::filesystem::gnocchi::runtime {

  include ::platform::filesystem::gnocchi::params
  $lv_name = $::platform::filesystem::gnocchi::params::lv_name
  $lv_size = $::platform::filesystem::gnocchi::params::lv_size
  $devmapper = $::platform::filesystem::gnocchi::params::devmapper

  platform::filesystem::resize { $lv_name:
    lv_name => $lv_name,
    lv_size => $lv_size,
    devmapper => $devmapper,
  }
}


class platform::filesystem::docker::runtime {

  include ::platform::filesystem::docker::params
  $lv_name = $::platform::filesystem::docker::params::lv_name
  $lv_size = $::platform::filesystem::docker::params::lv_size
  $devmapper = $::platform::filesystem::docker::params::devmapper

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
