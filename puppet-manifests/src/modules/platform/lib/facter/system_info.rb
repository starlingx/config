Facter.add("system_info") do
  setcode do
    Facter::Util::Resolution.exec('uname -r')
  end
end
