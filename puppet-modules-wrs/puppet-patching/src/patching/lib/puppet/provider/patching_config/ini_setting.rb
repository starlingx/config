#
# Copyright (c) 2014-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

Puppet::Type.type(:patching_config).provide(
  :ini_setting,
  :parent => Puppet::Type.type(:ini_setting).provider(:ruby)
) do

  def section
    resource[:name].split('/', 2).first
  end

  def setting
    resource[:name].split('/', 2).last
  end

  def separator
    '='
  end

  def self.file_path
    '/etc/patching/patching.conf'
  end

  # added for backwards compatibility with older versions of inifile
  def file_path
    self.class.file_path
  end

end
