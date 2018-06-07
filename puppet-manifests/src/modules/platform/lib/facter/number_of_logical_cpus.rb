# Returns number of logical cpus
Facter.add(:number_of_logical_cpus) do
  setcode "cat /proc/cpuinfo 2>/dev/null | awk '/^[pP]rocessor/ { n +=1 } END { print (n>0) ? n : 1}'"
end
