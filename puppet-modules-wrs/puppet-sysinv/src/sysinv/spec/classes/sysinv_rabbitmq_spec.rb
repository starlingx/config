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

describe 'sysinv::rabbitmq' do

  let :facts do
    { :puppetversion => '2.7',
      :osfamily      => 'Debian',
    }
  end

  describe 'with defaults' do

    it 'should contain all of the default resources' do

      should contain_class('rabbitmq::server').with(
        :service_ensure    => 'running',
        :port              => '5672',
        :delete_guest_user => false
      )

      should contain_rabbitmq_vhost('/').with(
        :provider => 'rabbitmqctl'
      )
    end

  end

  describe 'when a rabbitmq user is specified' do

    let :params do
      {
        :userid   => 'dan',
        :password => 'pass'
      }
    end

    it 'should contain user and permissions' do

      should contain_rabbitmq_user('dan').with(
        :admin    => true,
        :password => 'pass',
        :provider => 'rabbitmqctl'
      )

      should contain_rabbitmq_user_permissions('dan@/').with(
        :configure_permission => '.*',
        :write_permission     => '.*',
        :read_permission      => '.*',
        :provider             => 'rabbitmqctl'
      )

    end

  end

  describe 'when disabled' do
    let :params do
      {
        :userid   => 'dan',
        :password => 'pass',
        :enabled  => false
      }
    end

    it 'should be disabled' do

      should_not contain_rabbitmq_user('dan')
      should_not contain_rabbitmq_user_permissions('dan@/')
      should contain_class('rabbitmq::server').with(
        :service_ensure    => 'stopped',
        :port              => '5672',
        :delete_guest_user => false
      )

      should_not contain_rabbitmq_vhost('/')

    end
  end


end
