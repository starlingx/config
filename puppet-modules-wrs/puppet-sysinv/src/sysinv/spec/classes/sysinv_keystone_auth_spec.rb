#
# Files in this package are licensed under Apache; see LICENSE file.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#  Aug 2016: rebase mitaka
#  Jun 2016: rebase centos
#  Jun 2015: uprev kilo
#  Dec 2014: uprev juno
#  Jul 2014: rename ironic
#  Dec 2013: uprev grizzly, havana
#  Nov 2013: integrate source from https://github.com/stackforge/puppet-sysinv
#

require 'spec_helper'

describe 'sysinv::keystone::auth' do

  let :req_params do
    {:password => 'pw'}
  end

  describe 'with only required params' do

    let :params do
      req_params
    end

    it 'should contain auth info' do

      should contain_keystone_user('sysinv').with(
        :ensure   => 'present',
        :password => 'pw',
        :email    => 'sysinv@localhost',
        :tenant   => 'services'
      )
      should contain_keystone_user_role('sysinv@services').with(
        :ensure  => 'present',
        :roles   => 'admin'
      )
      # JKUNG commented this out for now, not volume
      # should contain_keystone_service('sysinv').with(
      #   :ensure      => 'present',
      #   :type        => 'volume',
      #   :description => 'Sysinv Service'
      # )

    end
    it { should contain_keystone_endpoint('RegionOne/sysinv').with(
      :ensure       => 'present',
      :public_url   => 'http://127.0.0.1:6385/v1/', #%(tenant_id)s',
      :admin_url    => 'http://127.0.0.1:6385/v1/', #%(tenant_id)s',
      :internal_url => 'http://127.0.0.1:6385/v1/'  #%(tenant_id)s'
    ) }

  end

  describe 'when endpoint should not be configured' do
    let :params do
      req_params.merge(:configure_endpoint => false)
    end
    it { should_not contain_keystone_endpoint('RegionOne/sysinv') }
  end

end
