# Returns true if restore is in progress

Facter.add("is_restore_in_progress") do
  setcode do
     File.exist?('/etc/platform/.restore_in_progress')
  end
end
