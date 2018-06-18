# Returns true if one GB pages is supported
Facter.add("is_gb_page_supported") do
  setcode do
      Facter::Core::Execution.exec('grep -q pdpe1gb /proc/cpuinfo')
      $?.exitstatus == 0
  end
end
