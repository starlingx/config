#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class SysinvLldpDriverBase(object):
    """Sysinv LLDP Driver Base Class."""

    @abc.abstractmethod
    def lldp_has_neighbour(self, name):
        pass

    @abc.abstractmethod
    def lldp_update(self):
        pass

    @abc.abstractmethod
    def lldp_agents_list(self):
        pass

    @abc.abstractmethod
    def lldp_neighbours_list(self):
        pass

    @abc.abstractmethod
    def lldp_agents_clear(self):
        pass

    @abc.abstractmethod
    def lldp_neighbours_clear(self):
        pass

    @abc.abstractmethod
    def lldp_update_systemname(self, systemname):
        pass
