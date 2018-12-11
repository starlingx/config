# Returns true if worker services should be disabled

Facter.add("disable_worker_services") do
  setcode do
    File.exist?('/var/run/.disable_worker_services')
  end
end
