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

describe 'sysinv::api' do

  let :req_params do
    {:keystone_password => 'foo'}
  end
  let :facts do
    {:osfamily => 'Debian'}
  end

  describe 'with only required params' do
    let :params do
      req_params
    end

    it { should contain_service('sysinv-api').with(
      'hasstatus' => true
    )}

    it 'should configure sysinv api correctly' do
      should contain_sysinv_config('DEFAULT/auth_strategy').with(
       :value => 'keystone'
      )
      #should contain_sysinv_config('DEFAULT/osapi_volume_listen').with(
      # :value => '0.0.0.0'
      #)
      should contain_sysinv_api_paste_ini('filter:authtoken/service_protocol').with(
        :value => 'http'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/service_host').with(
        :value => 'localhost'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/service_port').with(
        :value => '5000'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/auth_protocol').with(
        :value => 'http'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/auth_host').with(
        :value => 'localhost'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/auth_port').with(
        :value => '5000'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/auth_admin_prefix').with(
        :ensure => 'absent'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/admin_tenant_name').with(
        :value => 'services'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/admin_user').with(
        :value => 'sysinv'
      )
      should contain_sysinv_api_paste_ini('filter:authtoken/admin_password').with(
        :value  => 'foo',
        :secret => true
      )
    end
  end

  describe 'with only required params' do
    let :params do
      req_params.merge({'bind_host' => '192.168.1.3'})
    end
    # it 'should configure sysinv api correctly' do
    #  should contain_sysinv_config('DEFAULT/osapi_volume_listen').with(
    #   :value => '192.168.1.3'
    #  )
    # end
  end

  [ '/keystone', '/keystone/admin', '' ].each do |keystone_auth_admin_prefix|
    describe "with keystone_auth_admin_prefix containing incorrect value #{keystone_auth_admin_prefix}" do
      let :params do
        {
          :keystone_auth_admin_prefix => keystone_auth_admin_prefix,
          :keystone_password    => 'dummy'
        }
      end

      it { should contain_sysinv_api_paste_ini('filter:authtoken/auth_admin_prefix').with(
        :value => keystone_auth_admin_prefix
      )}
    end
  end

  [
    '/keystone/',
    'keystone/',
    'keystone',
    '/keystone/admin/',
    'keystone/admin/',
    'keystone/admin'
  ].each do |keystone_auth_admin_prefix|
    describe "with keystone_auth_admin_prefix containing incorrect value #{keystone_auth_admin_prefix}" do
      let :params do
        {
          :keystone_auth_admin_prefix => keystone_auth_admin_prefix,
          :keystone_password    => 'dummy'
        }
      end

      it { expect { should contain_sysinv_api_paste_ini('filter:authtoken/auth_admin_prefix') }.to \
        raise_error(Puppet::Error, /validate_re\(\): "#{keystone_auth_admin_prefix}" does not match/) }
    end
  end

end
