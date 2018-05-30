define qat_device_files(
  $qat_idx,
  $device_id,
) {
  if $device_id == "dh895xcc"{
      file { "/etc/dh895xcc_dev${qat_idx}.conf":
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0640',
        notify  => Service['qat_service'],
      }
  }

  if $device_id == "c62x"{
      file { "/etc/c62x_dev${qat_idx}.conf":
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0640',
        notify  => Service['qat_service'],
      }
  }
}

class platform::devices::qat (
  $device_config = {},
  $service_enabled = false
)
{
  if $service_enabled {
    create_resources('qat_device_files', $device_config)

    service { 'qat_service':
      ensure     => 'running',
      enable     => true,
      hasrestart => true,
      notify => Service['sysinv-agent'],
    }
  }
}

class platform::devices {
  include ::platform::devices::qat
}

