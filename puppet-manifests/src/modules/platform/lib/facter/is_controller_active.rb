# Check if current node is the active controller

require 'facter'

Facter.add("is_controller_active") do
  setcode do
    Facter::Core::Execution.exec("pgrep -f sysinv-api")
    $?.exitstatus == 0
  end
end
