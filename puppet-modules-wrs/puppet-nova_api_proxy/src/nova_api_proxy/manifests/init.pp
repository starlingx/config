#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  - Modify for integration
#

class nova_api_proxy (
) {

  Package['nova-api-proxy'] -> Proxy_config<||>
  Package['nova-api-proxy'] -> Proxy_api_paste_config<||>

  # This anchor is used to simplify the graph between nfv components
  # by allowing a resource to serve as a point where the configuration of
  # nfv begins
  anchor { 'proxy-start': }

  package { 'nova_api_proxy':
    name    => 'nova-api-proxy',
    require => Anchor['proxy-start'],
  }

  file { '/etc/proxy/nova-api-proxy.conf':
    ensure  => 'present',
    require => Package['nova-api-proxy'],
  }

}
