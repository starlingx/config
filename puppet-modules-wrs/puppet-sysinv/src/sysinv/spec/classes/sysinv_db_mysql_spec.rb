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

describe 'sysinv::db::mysql' do

  let :req_params do
    {:password => 'pw'}
  end

  let :facts do
    {:osfamily => 'Debian'}
  end

  let :pre_condition do
    'include mysql::server'
  end

  describe 'with only required params' do
    let :params do
      req_params
    end
    it { should contain_mysql__db('sysinv').with(
      :user         => 'sysinv',
      :password     => 'pw',
      :host         => '127.0.0.1',
      :charset      => 'latin1'
     ) }
  end
  describe "overriding allowed_hosts param to array" do
    let :params do
      {
        :password       => 'sysinvpass',
        :allowed_hosts  => ['127.0.0.1','%']
      }
    end

    it {should_not contain_sysinv__db__mysql__host_access("127.0.0.1").with(
      :user     => 'sysinv',
      :password => 'sysinvpass',
      :database => 'sysinv'
    )}
    it {should contain_sysinv__db__mysql__host_access("%").with(
      :user     => 'sysinv',
      :password => 'sysinvpass',
      :database => 'sysinv'
    )}
  end
  describe "overriding allowed_hosts param to string" do
    let :params do
      {
        :password       => 'sysinvpass2',
        :allowed_hosts  => '192.168.1.1'
      }
    end

    it {should contain_sysinv__db__mysql__host_access("192.168.1.1").with(
      :user     => 'sysinv',
      :password => 'sysinvpass2',
      :database => 'sysinv'
    )}
  end

  describe "overriding allowed_hosts param equals to host param " do
    let :params do
      {
        :password       => 'sysinvpass2',
        :allowed_hosts  => '127.0.0.1'
      }
    end

    it {should_not contain_sysinv__db__mysql__host_access("127.0.0.1").with(
      :user     => 'sysinv',
      :password => 'sysinvpass2',
      :database => 'sysinv'
    )}
  end
end
