# Returns true if compute services should be disabled

Facter.add("disable_compute_services") do
  setcode do
    File.exist?('/var/run/.disable_compute_services')
  end
end
