# Returns true if controllers are running the same software version (or if only
# one controller is configured). Will always return true if:
# 1. Manifests are being applied on any node other than a controller.
# 2. Manifests are being applied as part of a reconfig. Reconfigs can not be
#    done while a system is being upgraded.

Facter.add("controller_sw_versions_match") do
  setcode do
    ! (ENV['CONTROLLER_SW_VERSIONS_MISMATCH'] == "true")
  end
end
