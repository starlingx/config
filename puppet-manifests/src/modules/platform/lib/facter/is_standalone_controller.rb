# Returns true is this is the only configured controller in the system else
# return false if both controllers are configured. 

Facter.add("is_standalone_controller") do
  setcode do
    File.exist?('/etc/platform/simplex')
  end
end
