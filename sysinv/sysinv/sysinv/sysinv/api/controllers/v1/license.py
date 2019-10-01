# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#

import os
import pecan
from pecan import expose
from pecan import rest

from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.rpc.common import RemoteError
from tsconfig import tsconfig

LOG = log.getLogger(__name__)
LOCK_NAME = 'LicenseController'


class LicenseController(rest.RestController):
    """REST controller for license."""

    _custom_actions = {
        'install_license': ['POST'],
        'get_license_file': ['GET']
    }

    @expose('json')
    def get_license_file(self):
        license_file = tsconfig.PLATFORM_CONF_PATH + "/.license"
        content = ''
        error = ''
        if not os.path.isfile(license_file):
            error = "License file not found. " \
                    "A license may not have been installed."
        else:
            try:
                with open(license_file, 'r') as f:
                    content = f.read()
            except Exception:
                error = "Failed to read the license file"
        return dict(content=content, error=error)

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def install_license(self, file):
        file = pecan.request.POST['file']
        if not file.filename:
            return dict(success="", error="Error: No file uploaded")

        file.file.seek(0, os.SEEK_SET)
        contents = file.file.read()
        try:
            pecan.request.rpcapi.install_license_file(pecan.request.context, contents)
        except RemoteError as e:
            return dict(success="", error=e.value)
        except Exception as ex:
            return dict(success="", error=str(ex))

        return dict(success="Success: new license installed", error="")
