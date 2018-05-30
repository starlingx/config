# Returns true if cinder Ceph needs to be configured on current node  

Facter.add("is_node_cinder_ceph_config") do
  setcode do
    ! File.exist?('/etc/platform/.node_cinder_ceph_config_complete')
  end
end
