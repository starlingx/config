Facter.add(:platform_res_mem) do
  setcode "memtop | awk 'FNR == 3 {a=$13+$14} END {print a}'"
end
