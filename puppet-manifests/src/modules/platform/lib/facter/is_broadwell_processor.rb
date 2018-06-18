# Returns true if it is Broadwell processor
# Broadwell specific flags (model: 79)
Facter.add("is_broadwell_processor") do
  setcode do
      Facter::Core::Execution.exec('grep -q -E "^model\s+:\s+79$" /proc/cpuinfo')
      $?.exitstatus == 0
  end
end
