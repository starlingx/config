# -*- encoding: utf-8 -*-
#
# Copyright © 2012 New Dream Network, LLC (DreamHost)
#
# Author: Doug Hellmann <doug.hellmann@dreamhost.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import pecan
from pecan import rest

from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers import v1
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import link


class Version(base.APIBase):
    """An API version representation."""

    id = wtypes.text
    "The ID of the version, also acts as the release number"

    links = [link.Link]
    "A Link that point to a specific version of the API"

    @classmethod
    def convert(self, id):
        version = Version()
        version.id = id
        version.links = [link.Link.make_link('self', pecan.request.host_url,
                                             id, '', bookmark=True)]
        return version


class Root(base.APIBase):

    name = wtypes.text
    "The name of the API"

    description = wtypes.text
    "Some information about this API"

    versions = [Version]
    "Links to all the versions available in this API"

    default_version = Version
    "A link to the default version of the API"

    @classmethod
    def convert(self):
        root = Root()
        root.name = "Titanium SysInv API"
        root.description = ("Titanium Cloud System API allows for the "
             "management of physical servers.  This includes inventory "
             "collection and configuration of hosts, ports, interfaces, CPUs, disk, "
             "memory, and system configuration.  The API also supports "
             "alarms and fault collection for the cloud itself."
                            )
        root.versions = [Version.convert('v1')]
        root.default_version = Version.convert('v1')
        return root


class RootController(rest.RestController):

    v1 = v1.Controller()

    @wsme_pecan.wsexpose(Root)
    def get(self):
        # NOTE: The reason why convert() it's being called for every
        #       request is because we need to get the host url from
        #       the request object to make the links.
        return Root.convert()

    @pecan.expose()
    def options(self):
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        pecan.response.headers['Allow'] = ', '.join(allowed_methods)
        return
