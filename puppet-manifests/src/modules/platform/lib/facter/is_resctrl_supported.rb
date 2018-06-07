# Returns true if Resource Control is supported on this node
Facter.add("is_resctrl_supported") do
  setcode do
    Dir.exist?('/sys/fs/resctrl')
  end
end
