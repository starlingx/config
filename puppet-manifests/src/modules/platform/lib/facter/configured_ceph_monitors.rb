Facter.add("configured_ceph_monitors") do
  setcode do
    lines = IO.readlines("/etc/ceph/ceph.conf").keep_if { |v| v =~ /\[mon\..*\]/ }
    lines.collect do |line|
      line.scan(/\[mon\.(.*)\]/).last.first
    end
  end
end
