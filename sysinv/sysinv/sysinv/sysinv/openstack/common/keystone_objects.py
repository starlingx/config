#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import datetime
import iso8601

from oslo_log import log

LOG = log.getLogger(__name__)


class Token(object):
    """Represents a keystone token"""
    def __init__(self,
                 token_data,
                 token_id,
                 region_name):
        """Intialize the token.

        token_data: The token data, converted from json
        token_id: The id
        region_name: The default region name for this token
                     Note: universal (project-scoped) tokens will contain
                     other region names in the token catalog data.
        """
        self.expired = False
        self.data = token_data
        self.token_id = token_id
        self.region_name = region_name

    def set_expired(self):
        """Mark this token as expired"""
        self.expired = True

    def is_expired(self, within_seconds=300):
        """Check if expired or will expire within given number of seconds"""
        if not self.expired:
            end = iso8601.parse_date(self.data['token']['expires_at'])
            now = iso8601.parse_date(datetime.datetime.utcnow().isoformat())
            # don't use .seconds here since it will be only the 'seconds' part
            # of the timedelta
            delta = (end - now).total_seconds()
            return delta <= within_seconds
        return True

    def get_id(self):
        """Get the identifier of the token.
        """
        return self.token_id

    def _get_service_url(self,
                         service_type,
                         service_name,
                         interface_type,
                         region_name):
        """
        Search the catalog of a service for the url based on the interface
        Returns: url or None on failure
        """
        if region_name is None:
            region_name = self.region_name
        for catalog in self.data['token']['catalog']:
            if (catalog['type'] == service_type
                    and catalog['name'] == service_name
                    and len(catalog['endpoints']) != 0):
                for endpoint in catalog['endpoints']:
                    if (endpoint['interface'] == interface_type
                            and endpoint['region'] == region_name):
                        return endpoint['url']
        return None

    def get_service_admin_url(self,
                              service_type,
                              service_name,
                              region_name=None):
        """Search the catalog of a service for the administrative url
        Returns: admin url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'admin',
                                     region_name)

    def update_service_admin_url(
            self, service_type, service_name, region_name, endpoint):
        """Update the catalog of a service for the administrative url"""
        return self._set_service_url(service_type, service_name,
                                     'admin', region_name, endpoint)

    def _set_service_url(self, service_type, service_name, interface_type,
                         region_name, new_endpoint):
        """Update the url of a service in a region"""
        if region_name is None:
            region_name = self.region_name
        for catalog in self.data['token']['catalog']:
            if (catalog['type'] == service_type and
                    catalog['name'] == service_name and
                    catalog['endpoints']):
                for endpoint in catalog['endpoints']:
                    if (endpoint['interface'] == interface_type
                            and endpoint['region'] == region_name):
                        endpoint['url'] = new_endpoint

    def get_service_internal_url(self,
                                 service_type,
                                 service_name,
                                 region_name=None):
        """Search the catalog of a service for the internal url
        Returns: internal url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'internal',
                                     region_name)

    def get_service_public_url(self,
                               service_type,
                               service_name,
                               region_name=None):
        """Search the catalog of a service for the public url
        Returns: public url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'public',
                                     region_name)

    def get_service_url(self, service_type, service_name, region_name=None):
        """Search the catalog of a service for the administrative url
        Returns: admin url or None on failure
        """
        return self.get_service_admin_url(service_type, service_name,
                                          region_name)

    def get_full_str(self):
        """Formats the entire token, used only for debugging."""
        return "id: {}, expired: {}, region_name: {}, expires_at: {}, data: {}"\
            .format(self.token_id, self.expired, self.region_name,
                    self.data['token']['expires_at'], self.data)

    def __str__(self):
        return "id: {}, expired: {}, region_name: {}, expires_at: {}".format(
            self.token_id, self.expired, self.region_name,
            self.data['token']['expires_at'])
