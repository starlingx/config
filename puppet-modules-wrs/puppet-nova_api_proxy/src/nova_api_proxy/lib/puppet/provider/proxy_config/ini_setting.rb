#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  - Modify for integration
#

Puppet::Type.type(:proxy_config).provide(
  :ini_setting,
  :parent => Puppet::Type.type(:ini_setting).provider(:ruby)
) do

  # the setting is always default
  # this if for backwards compat with the old puppet providers for nova_config
  def section
    resource[:name].split('/', 2)[0]
  end

  # assumes that the name was the setting
  # this is to maintain backwards compat with the the older
  # stuff
  def setting
    resource[:name].split('/', 2)[1]
  end

  def separator
    '='
  end

  def self.file_path
    '/etc/proxy/nova-api-proxy.conf'
  end

  # added for backwards compatibility with older versions of inifile
  def file_path
    self.class.file_path
  end

end
