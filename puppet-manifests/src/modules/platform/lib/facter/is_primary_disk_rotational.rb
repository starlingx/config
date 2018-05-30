require 'facter'
Facter.add(:is_primary_disk_rotational) do
  rootfs_partition = Facter::Core::Execution.exec("df --output=source / | tail -1")
  rootfs_device = Facter::Core::Execution.exec("basename #{rootfs_partition} | sed 's/[0-9]*$//;s/p[0-9]*$//'")
  setcode "cat /sys/block/#{rootfs_device}/queue/rotational"
end
