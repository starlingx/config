#
# Copyright (c) 2014-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
OpenStack Keystone Interactions
"""

import datetime
import iso8601

from exceptions import KeystoneFail
import log


LOG = log.get_logger(__name__)


class Token(object):
    def __init__(self, token_data, token_id):
        self._expired = False
        self._data = token_data
        self._token_id = token_id

    def set_expired(self):
        """ Indicate token is expired """
        self._expired = True

    def is_expired(self, within_seconds=300):
        """ Check if token is expired """
        if not self._expired:
            end = iso8601.parse_date(self._data['token']['expires_at'])
            now = iso8601.parse_date(datetime.datetime.utcnow().isoformat())
            delta = abs(end - now).seconds
            return delta <= within_seconds
        return True

    def get_id(self):
        """ Get the identifier of the token """
        return self._token_id

    def get_service_admin_url(self, service_type, service_name, region_name):
        """ Search the catalog of a service for the administrative url """
        return self.get_service_url(region_name, service_name,
                                    service_type, 'admin')

    def get_service_url(self, region_name, service_name, service_type,
                        endpoint_type):
        """
        Search the catalog of a service in a region for the url
        """
        for catalog in self._data['token']['catalog']:
            if catalog['type'] == service_type:
                if catalog['name'] == service_name:
                    if 0 != len(catalog['endpoints']):
                        for endpoint in catalog['endpoints']:
                            if (endpoint['region'] == region_name and
                                    endpoint['interface'] == endpoint_type):
                                return endpoint['url']

        raise KeystoneFail((
            "Keystone service type %s, name %s, region %s, endpoint type %s "
            "not available" %
            (service_type, service_name, region_name, endpoint_type)))


class Service(object):
    """
    Keystone Service
    """
    def __init__(self, service_data):
        self._data = service_data

    def get_id(self):
        if 'id' in self._data['service']:
            return self._data['service']['id']
        return None


class ServiceList(object):
    """
    Keystone Service List
    """
    def __init__(self, service_data):
        self._data = service_data

    def get_service_id(self, name, type):
        """
        Search the services for the id
        """
        for service in self._data['services']:
            if service['name'] == name:
                if service['type'] == type:
                    return service['id']

        raise KeystoneFail((
            "Keystone service type %s, name %s not available" %
            (type, name)))


class Project(object):
    """
    Keystone Project
    """
    def __init__(self, project_data):
        self._data = project_data

    def get_id(self):
        if 'id' in self._data['project']:
            return self._data['project']['id']
        return None


class ProjectList(object):
    """
    Keystone Project List
    """
    def __init__(self, project_data):
        self._data = project_data

    def get_project_id(self, name):
        """
        Search the projects for the id
        """
        for project in self._data['projects']:
            if project['name'] == name:
                return project['id']
        return None


class Endpoint(object):
    """
    Keystone Endpoint
    """
    def __init__(self, endpoint_data):
        self._data = endpoint_data

    def get_id(self):
        if 'id' in self._data['endpoint']:
            return self._data['endpoint']['id']
        return None


class EndpointList(object):
    """
    Keystone Endpoint List
    """
    def __init__(self, endpoint_data):
        self._data = endpoint_data

    def get_service_url(self, region_name, service_id, endpoint_type):
        """
        Search the endpoints for the url
        """
        for endpoint in self._data['endpoints']:
            if endpoint['service_id'] == service_id:
                if (endpoint['region'] == region_name and
                        endpoint['interface'] == endpoint_type):
                    return endpoint['url']

        raise KeystoneFail((
            "Keystone service id %s, region %s, endpoint type %s not "
            "available" % (service_id, region_name, endpoint_type)))


class User(object):
    """
    Keystone User
    """
    def __init__(self, user_data):
        self._data = user_data

    def get_user_id(self):
        return self._data['user']['id']


class UserList(object):
    """
    Keystone User List
    """
    def __init__(self, user_data):
        self._data = user_data

    def get_user_id(self, name):
        """
        Search the users for the id
        """
        for user in self._data['users']:
            if user['name'] == name:
                return user['id']
        return None


class Role(object):
    """
    Keystone Role
    """
    def __init__(self, role_data):
        self._data = role_data


class RoleList(object):
    """
    Keystone Role List
    """
    def __init__(self, role_data):
        self._data = role_data

    def get_role_id(self, name):
        """
        Search the roles for the id
        """
        for role in self._data['roles']:
            if role['name'] == name:
                return role['id']
        return None


class Domain(object):
    """
    Keystone Domain
    """
    def __init__(self, user_data):
        self._data = user_data

    def get_domain_id(self):
        return self._data['domain']['id']


class DomainList(object):
    """
    Keystone Domain List
    """
    def __init__(self, user_data):
        self._data = user_data

    def get_domain_id(self, name):
        """
        Search the domains for the id
        """
        for domain in self._data['domains']:
            if domain['name'] == name:
                return domain['id']
        return None
