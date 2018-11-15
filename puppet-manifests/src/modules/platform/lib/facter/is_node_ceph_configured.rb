# Returns true if Ceph has been configured on current node

Facter.add("is_node_ceph_configured") do
  setcode do
    File.exist?('/etc/platform/.node_ceph_configured')
  end
end
