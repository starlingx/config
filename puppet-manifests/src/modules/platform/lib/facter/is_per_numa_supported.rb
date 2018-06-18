# Returns true if Resource Control is supported on this node
Facter.add("is_per_numa_supported") do
  setcode do
    Dir.exist?('/sys/devices/system/node/node0')
  end
end
