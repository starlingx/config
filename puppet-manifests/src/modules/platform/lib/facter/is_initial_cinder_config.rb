# Returns true is this is the initial cinder config for this system

Facter.add("is_initial_cinder_config") do
  setcode do
    conf_path = Facter::Core::Execution.exec("hiera --config /etc/puppet/hiera.yaml platform::params::config_path")
    ! File.exist?(conf_path + '.initial_cinder_config_complete')
  end
end
