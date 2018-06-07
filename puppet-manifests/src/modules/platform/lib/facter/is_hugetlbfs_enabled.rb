# Returns true if hugetlbfs not enabled
Facter.add("is_hugetlbfs_enabled") do
  setcode do
      Facter::Core::Execution.exec('grep -q hugetlbfs /proc/filesystems')
      $?.exitstatus == 0
  end
end
