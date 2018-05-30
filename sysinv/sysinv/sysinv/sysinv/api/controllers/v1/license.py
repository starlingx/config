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
# Copyright (c) 2017 Wind River Systems, Inc.
#

import os
from tsconfig.tsconfig import CONFIG_PATH
import pecan
from pecan import expose
from pecan import rest
from platform_util.license import license

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import utils
from sysinv.common import utils as cutils
from sysinv.common import constants

from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class License(base.APIBase):
    """API representation of a license.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a license.
    """

    name = wtypes.text
    "Name of the license"

    status = wtypes.text
    "Status of the license"

    expiry_date = wtypes.text
    "Expiry date of the license"

    links = [link.Link]
    "A list containing a self link and associated license links"

    def __init__(self, **kwargs):
        self.fields = []

        # they are all an API-only attribute
        for fp in ['name','status','expiry_date']:
            self.fields.append(fp)
            setattr(self, fp, kwargs.get(fp, None))

    @classmethod
    def convert_with_links(cls, rpc_license, expand=True):

        license = License(**rpc_license)
        if not expand:
            license.unset_fields_except(['name','status',
                                         'expiry_date'])

        return license


class LicenseCollection(collection.Collection):
    """API representation of a collection of licenses."""

    licenses = [License]
    "A list containing License objects"

    def __init__(self, **kwargs):
        self._type = "licenses"

    @classmethod
    def convert_with_links(cls, rpc_license, limit, url=None,
                           expand=False, **kwargs):
        collection = LicenseCollection()
        collection.licenses = [License.convert_with_links(n, expand)
                               for n in rpc_license]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LicenseController'


class LicenseController(rest.RestController):
    """REST controller for license."""

    _custom_actions = {
        'install_license': ['POST'],
    }

    def _get_license_collection(self, marker, limit, sort_key, sort_dir, expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        licenses = license.get_licenses_info()

        return LicenseCollection.convert_with_links(
            licenses, limit, url=resource_url,expand=expand,
            sort_key=sort_key,sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LicenseCollection, wtypes.text, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        return self._get_license_collection(marker, limit, sort_key, sort_dir)

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
        except Exception as e:
            return dict(success="", error=e.value)

        return dict(success="Success: new license installed", error="")
