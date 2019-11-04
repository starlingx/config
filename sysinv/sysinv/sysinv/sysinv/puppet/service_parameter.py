#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging
from sysinv.common import service_parameter
from sysinv.puppet import base

LOG = logging.getLogger(__name__)


class ServiceParamPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for service parameters"""

    def _format_array_parameter(self, resource, value):
        parameter = {}
        if value != 'undef':
            param_array = []
            for p in value.split(","):
                param_array.append(p)
            parameter[resource] = param_array

        return parameter

    def _format_boolean_parameter(self, resource, value):
        return {resource: bool(value.lower() == 'true')}

    def get_system_config(self):
        config = {}
        service_parameters = self._get_service_parameters()

        if service_parameters is None:
            return config

        for param in service_parameters:
            if param.personality is not None:
                # Personality-restricted parameters are handled in host function
                continue

            if param.resource is not None:
                config.update({param.resource: param.value})
                continue

            # Add supported parameter
            if param.service not in service_parameter.SERVICE_PARAMETER_SCHEMA \
                    or param.section not in service_parameter.SERVICE_PARAMETER_SCHEMA[param.service]:
                continue

            schema = service_parameter.SERVICE_PARAMETER_SCHEMA[param.service][param.section]
            if service_parameter.SERVICE_PARAM_RESOURCE not in schema:
                continue

            resource = schema[service_parameter.SERVICE_PARAM_RESOURCE].get(param.name)
            if resource is None:
                continue

            formatter = None

            if service_parameter.SERVICE_PARAM_DATA_FORMAT in schema:
                formatter = schema[service_parameter.SERVICE_PARAM_DATA_FORMAT].get(param.name)

            if formatter == service_parameter.SERVICE_PARAMETER_DATA_FORMAT_SKIP:
                # Parameter is handled elsewhere
                continue
            elif formatter == service_parameter.SERVICE_PARAMETER_DATA_FORMAT_ARRAY:
                config.update(self._format_array_parameter(resource, param.value))
            elif formatter == service_parameter.SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN:
                config.update(self._format_boolean_parameter(resource, param.value))
            else:
                config.update({resource: param.value})

        return config

    def get_host_config(self, host):
        config = {}
        service_parameters = self._get_service_parameters()

        if service_parameters is None:
            return config

        for param in service_parameters:
            # Only custom parameters support personality filters
            if param.personality is None or param.personality != host.personality \
                    or param.resource is None:
                continue

            config.update({param.resource: param.value})

        return config
