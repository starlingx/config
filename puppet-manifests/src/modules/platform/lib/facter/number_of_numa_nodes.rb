# Returns number of numa nodes
Facter.add(:number_of_numa_nodes) do
  setcode "ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l"
end
