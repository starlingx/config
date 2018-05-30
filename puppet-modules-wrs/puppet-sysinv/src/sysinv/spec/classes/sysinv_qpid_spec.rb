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

describe 'sysinv::qpid' do

  let :facts do
    {:puppetversion => '2.7',
     :osfamily => 'RedHat'}
  end

  describe 'with defaults' do

    it 'should contain all of the default resources' do

      should contain_class('qpid::server').with(
        :service_ensure    => 'running',
        :port              => '5672'
      )

    end

    it 'should contain user' do

      should contain_qpid_user('guest').with(
        :password => 'guest',
        :file     => '/var/lib/qpidd/qpidd.sasldb',
        :realm    => 'OPENSTACK',
        :provider => 'saslpasswd2'
      )

    end

  end

  describe 'when disabled' do
    let :params do
      {
        :enabled  => false
      }
    end

    it 'should be disabled' do

      should_not contain_qpid_user('guest')
      should contain_class('qpid::server').with(
        :service_ensure    => 'stopped'
      )

    end
  end

end
