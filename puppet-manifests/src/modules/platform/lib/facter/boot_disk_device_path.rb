Facter.add("boot_disk_device_path") do
  setcode do
    Facter::Util::Resolution.exec('find -L /dev/disk/by-path/ -samefile $(df --output=source /boot | tail -1) | tail -1')
  end
end
