# Returns the current boot parameters
Facter.add(:get_cmdline) do
  setcode "cat /proc/cmdline 2>/dev/null"
end

