# Returns true is this is the primary initial config (ie. first controller)

Facter.add("is_initial_config_primary") do
  setcode do
    ENV['INITIAL_CONFIG_PRIMARY'] == "true"
  end
end

