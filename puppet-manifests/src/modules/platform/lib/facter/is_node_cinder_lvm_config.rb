# Returns true if cinder LVM needs to be configured on current node

Facter.add("is_node_cinder_lvm_config") do
  setcode do
    ! File.exist?('/etc/platform/.node_cinder_lvm_config_complete')
  end
end
