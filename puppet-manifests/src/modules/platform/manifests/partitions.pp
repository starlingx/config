class platform::partitions::params (
  $create_config = undef,
  $modify_config = undef,
  $shutdown_drbd_resource = undef,
  $delete_config = undef,
  $check_config = undef,
) {}


define platform_manage_partition(
  $action = $name,
  $config = undef,
  $shutdown_drbd_resource = undef,
  $system_mode = undef,
) {
  if $config {
    # For drbd partitions, modifications can only be done on standby
    # controller as we need to:
    # - stop DRBD [drbd is in-use on active, so it can't be stopped there]
    # - manage-partitions: backup meta, resize partition, restore meta
    # - start DRBD
    # For AIO SX we make an exception as all instances are down on host lock.
    # see https://docs.linbit.com/doc/users-guide-83/s-resizing/
    exec { "manage-partitions-${action}":
      logoutput => true,
      command   => template('platform/partitions.manage.erb')
    }
  }
}


class platform::partitions
  inherits ::platform::partitions::params {

  # Ensure partitions are updated before the PVs and VGs are setup
  Platform_manage_partition <| |> -> Physical_volume <| |>
  Platform_manage_partition <| |> -> Volume_group <| |>

  # Perform partition updates in a particular order: deletions,
  # modifications, then creations.

  # NOTE: Currently we are executing partition changes serially, not in bulk.
  platform_manage_partition { 'check':
    config => $check_config,
  }
  -> platform_manage_partition { 'delete':
    config => $delete_config,
  }
  -> platform_manage_partition { 'modify':
    config                 => $modify_config,
    shutdown_drbd_resource => $shutdown_drbd_resource,
    system_mode            => $::platform::params::system_mode,
  }
  -> platform_manage_partition { 'create':
    config => $create_config,
  }
}


class platform::partitions::runtime {
  include ::platform::partitions
}
