# Returns number of physical cores
Facter.add(:physical_core_count) do
  setcode "awk '/^cpu cores/ {c=$4} /physical id/ {a[$4]=1} END {n=0; for (i in a) n++; print (n>0 && c>0) ? n*c : 1}' /proc/cpuinfo"
end
