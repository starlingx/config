# Returns true is this is the initial config for this node

Facter.add("is_initial_config") do
  setcode do
    ! File.exist?('/etc/platform/.initial_config_complete')
  end
end
