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
    def __init__(self, token_data, token_id, region_name):
        self.expired = False
        self.data = token_data
        self.token_id = token_id
        self.region_name = region_name

    def set_expired(self):
        self.expired = True

    def is_expired(self, within_seconds=300):
        if not self.expired:
            end = iso8601.parse_date(self.data['token']['expires_at'])
            now = iso8601.parse_date(datetime.datetime.utcnow().isoformat())
            # don't use .seconds here since it will be only the 'seconds' part
            # of the timedelta
            delta = (end - now).total_seconds()
            return delta <= within_seconds
        return True

    def get_id(self):
        """
        Get the identifier of the token.
        """
        return self.token_id

    def _get_service_url(self, service_type, service_name, interface_type):
        """
        Search the catalog of a service for the url based on the interface
        Returns: url or None on failure
        """
        for catalog in self.data['token']['catalog']:
            if catalog['type'] == service_type:
                if catalog['name'] == service_name:
                    if len(catalog['endpoints']) != 0:
                        for endpoint in catalog['endpoints']:
                            if ((endpoint['interface'] == interface_type) and
                                    (endpoint['region'] == self.region_name)):
                                return endpoint['url']
        return None

    def get_service_admin_url(self, service_type, service_name):
        """
        Search the catalog of a service for the administrative url
        Returns: admin url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'admin')

    def get_service_internal_url(self, service_type, service_name):
        """
        Search the catalog of a service for the administrative url
        Returns: admin url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'internal')

    def get_service_public_url(self, service_type, service_name):
        """
        Search the catalog of a service for the administrative url
        Returns: admin url or None on failure
        """
        return self._get_service_url(service_type, service_name, 'public')

    def get_service_url(self, service_type, service_name):
        return self.get_service_admin_url(service_type, service_name)

    def __str__(self):
        return "id: {}, expired: {}, region_name: {}, expires_at: {}".format(
            self.token_id, self.expired, self.region_name,
            self.data['token']['expires_at'])
