# Platform reserved memory is the total normal memory (i.e. 4K memory) that
# may be allocated by programs in MiB. This total excludes huge-pages and
# kernel overheads.
#
# The 'MemAvailable' field represents total unused memory. This includes:
# free, buffers, cached, and reclaimable slab memory.
#
# The Active(anon) and Inactive(anon) fields represents the total used
# anonymous memory.
Facter.add(:platform_res_mem) do
  setcode "grep -e '^MemAvailable:' -e '^Active(anon):' -e '^Inactive(anon):' /proc/meminfo | awk '{a+=$2} END{print int(a/1024)}'"
end
