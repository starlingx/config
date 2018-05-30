# Returns whether keystone is running on the local host
Facter.add(:is_keystone_running) do
  setcode do
      Facter::Util::Resolution.exec('pgrep -c -f "\[keystone\-admin\]"') != '0'
  end
end
