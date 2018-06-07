module Puppet::Parser::Functions
  newfunction(:check_grub_config,
              :type => :rvalue,
              :doc => <<-EOD
    This internal function checks if a list of arguments are configured
    in the current boot args based on the input parameters

    EOD
    ) do |args|

    func_name = "check_grub_config()"

    raise(Puppet::ParseError, "#{func_name}: Requires 1 argument" +
      "#{args.size} given") if args.size != 1

    expected = args[0]
    raise(Puppet::ParseError, "#{func_name}: first argument must be a string") \
      unless expected.instance_of? String

    # get the current boot args
    cmd = Facter.value(:get_cmdline)
    cmd_array = cmd.split()

    value = true
    expected.split().each do |element|
      value = cmd_array.include?(element)
      if value == false
        Puppet.debug("#{element} is not presented in #{cmd}")
        return value
      end
    end
    value
  end
end
