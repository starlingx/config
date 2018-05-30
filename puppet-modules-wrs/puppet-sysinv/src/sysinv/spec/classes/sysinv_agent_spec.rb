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

describe 'sysinv::agent' do

  describe 'on debian plateforms' do

    let :facts do
      { :osfamily => 'Debian' }
    end

    describe 'with default parameters' do

      it { should include_class('sysinv::params') }

      it { should contain_package('sysinv-agent').with(
        :name      => 'sysinv-agent',
        :ensure    => 'latest',
        :before    => 'Service[sysinv-agent]'
      ) }

      it { should contain_service('sysinv-agent').with(
        :name      => 'sysinv-agent',
        :enable    => true,
        :ensure    => 'running',
        :require   => 'Package[sysinv]',
        :hasstatus => true
      ) }
    end

    describe 'with parameters' do

      let :params do
        { :agent_driver => 'sysinv.agent.filter_agent.FilterScheduler',
          :package_ensure   => 'present'
        }
      end

      it { should contain_sysinv_config('DEFAULT/agent_driver').with_value('sysinv.agent.filter_agent.FilterScheduler') }
      it { should contain_package('sysinv-agent').with_ensure('present') }
    end
  end


  describe 'on rhel plateforms' do

    let :facts do
      { :osfamily => 'RedHat' }
    end

    describe 'with default parameters' do

      it { should include_class('sysinv::params') }

      it { should contain_service('sysinv-agent').with(
        :name    => 'sysinv-agent',
        :enable  => true,
        :ensure  => 'running',
        :require => 'Package[sysinv]'
      ) }
    end

    describe 'with parameters' do

      let :params do
        { :agent_driver => 'sysinv.agent.filter_agent.FilterScheduler' }
      end

      it { should contain_sysinv_config('DEFAULT/agent_driver').with_value('sysinv.agent.filter_agent.FilterScheduler') }
    end
  end
end
