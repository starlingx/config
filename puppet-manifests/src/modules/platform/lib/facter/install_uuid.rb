Facter.add("install_uuid") do
  setcode do
    Facter::Util::Resolution.exec("awk -F= '{if ($1 == \"INSTALL_UUID\") { print $2; }}' /etc/platform/platform.conf")
  end
end

