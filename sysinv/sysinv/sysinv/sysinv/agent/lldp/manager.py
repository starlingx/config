#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from oslo_config import cfg
from oslo_log import log
from stevedore.named import NamedExtensionManager
from sysinv.common import exception

LOG = log.getLogger(__name__)
cfg.CONF.import_opt('drivers',
                    'sysinv.agent.lldp.config',
                    group='lldp')


class SysinvLldpDriverManager(NamedExtensionManager):
    """Implementation of Sysinv LLDP drivers."""

    def __init__(self, namespace='sysinv.agent.lldp.drivers'):

        # Registered sysinv lldp agent drivers, keyed by name.
        self.drivers = {}

        # Ordered list of sysinv lldp agent drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []

        names = cfg.CONF.lldp.drivers
        LOG.info("Configured sysinv LLDP agent drivers: %s", names)

        super(SysinvLldpDriverManager, self).__init__(
            namespace,
            names,
            invoke_on_load=True,
            name_order=True)

        LOG.info("Loaded sysinv LLDP agent drivers: %s", self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all sysinv LLDP agent drivers.

        This method should only be called once in the
        SysinvLldpDriverManager constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info("Registered sysinv LLDP agent drivers: %s",
                 [driver.name for driver in self.ordered_drivers])

    def _call_drivers_and_return_array(self, method_name, attr=None,
                                       raise_orig_exc=False):
        """Helper method for calling a method across all drivers.

        :param method_name: name of the method to call
        :param attr: an optional attribute to provide to the drivers
        :param raise_orig_exc: whether or not to raise the original
        driver exception, or use a general one
        """
        ret = []
        for driver in self.ordered_drivers:
            try:
                method = getattr(driver.obj, method_name)
                if attr:
                    ret = ret + method(attr)
                else:
                    ret = ret + method()
            except Exception as e:
                LOG.exception(e)
                LOG.error(
                    "Sysinv LLDP agent driver '%(name)s' "
                    "failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                if raise_orig_exc:
                    raise
                else:
                    raise exception.LLDPDriverError(
                        method=method_name
                    )
        return list(set(ret))

    def _call_drivers(self, method_name, attr=None, raise_orig_exc=False):
        """Helper method for calling a method across all drivers.

        :param method_name: name of the method to call
        :param attr: an optional attribute to provide to the drivers
        :param raise_orig_exc: whether or not to raise the original
        driver exception, or use a general one
        """
        for driver in self.ordered_drivers:
            try:
                method = getattr(driver.obj, method_name)
                if attr:
                    method(attr)
                else:
                    method()
            except Exception as e:
                LOG.exception(e)
                LOG.error(
                    "Sysinv LLDP agent driver '%(name)s' "
                    "failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                if raise_orig_exc:
                    raise
                else:
                    raise exception.LLDPDriverError(
                        method=method_name
                    )

    def lldp_has_neighbour(self, name):
        try:
            return self._call_drivers("lldp_has_neighbour",
                                      attr=name,
                                      raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return []

    def lldp_update(self):
        try:
            return self._call_drivers("lldp_update",
                                      raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return []

    def lldp_agents_list(self):
        try:
            return self._call_drivers_and_return_array("lldp_agents_list",
                                                       raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return []

    def lldp_neighbours_list(self):
        try:
            return self._call_drivers_and_return_array("lldp_neighbours_list",
                                                       raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return []

    def lldp_agents_clear(self):
        try:
            return self._call_drivers("lldp_agents_clear",
                                      raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return

    def lldp_neighbours_clear(self):
        try:
            return self._call_drivers("lldp_neighbours_clear",
                                      raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return

    def lldp_update_systemname(self, systemname):
        try:
            return self._call_drivers("lldp_update_systemname",
                                      attr=systemname,
                                      raise_orig_exc=True)
        except Exception as e:
            LOG.exception(e)
            return
