# Returns true is this is the initial kubernetes config for this node

Facter.add("is_initial_k8s_config") do
  setcode do
    ! File.exist?('/etc/platform/.initial_k8s_config_complete')
  end
end
