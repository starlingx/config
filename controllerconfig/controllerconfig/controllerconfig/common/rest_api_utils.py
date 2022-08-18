"""
Copyright (c) 2015-2020 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import json

from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common import keystone
from six.moves import http_client as httplib
from six.moves.urllib import request as urlrequest
from six.moves.urllib.error import HTTPError
from six.moves.urllib.error import URLError
from oslo_log import log


LOG = log.getLogger(__name__)


def rest_api_request(token, method, api_cmd, api_cmd_headers=None,
                     api_cmd_payload=None, timeout=30):
    """
    Make a rest-api request
    """
    try:
        request_info = urlrequest.Request(api_cmd)
        request_info.get_method = lambda: method
        request_info.add_header("X-Auth-Token", token.get_id())
        request_info.add_header("Accept", "application/json")

        if api_cmd_headers is not None:
            for header_type, header_value in api_cmd_headers.items():
                request_info.add_header(header_type, header_value)

        if api_cmd_payload is not None:
            request_info.add_header("Content-type", "application/json")
            request_info.data = api_cmd_payload

        request = urlrequest.urlopen(request_info, timeout=timeout)
        response = request.read()

        if response == "":
            response = json.loads("{}")
        else:
            response = json.loads(response)
        request.close()

        return response

    except HTTPError as e:
        if httplib.UNAUTHORIZED == e.code:
            token.set_expired()
        LOG.exception(e)
        raise KeystoneFail(
            "REST API HTTP Error for url: %s. Error: %s" %
            (api_cmd, e))

    except (URLError, httplib.BadStatusLine) as e:
        LOG.exception(e)
        raise KeystoneFail(
            "REST API URL Error for url: %s. Error: %s" %
            (api_cmd, e))


def get_token(auth_url, auth_project, auth_user, auth_password,
              user_domain, project_domain, timeout=30):
    """
    Ask OpenStack Keystone for a token
    """
    try:
        url = auth_url + "/auth/tokens"
        request_info = urlrequest.Request(url)
        request_info.add_header("Content-Type", "application/json")
        request_info.add_header("Accept", "application/json")

        payload = json.dumps(
            {"auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "name": auth_user,
                            "password": auth_password,
                            "domain": {"name": user_domain}
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": auth_project,
                        "domain": {"name": project_domain}
                    }}}})

        request_info.data = payload

        request = urlrequest.urlopen(request_info, timeout=timeout)
        # Identity API v3 returns token id in X-Subject-Token
        # response header.
        token_id = request.info().getheader('X-Subject-Token')
        response = json.loads(request.read())
        request.close()

        return keystone.Token(response, token_id)

    except HTTPError as e:
        LOG.error("%s, %s" % (e.code, e.read()))
        return None

    except (URLError, httplib.BadStatusLine) as e:
        LOG.error(e)
        return None


def get_services(token, api_url):
    """
    Ask OpenStack Keystone for a list of services
    """
    api_cmd = api_url + "/services"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.ServiceList(response)


def create_service(token, api_url, name, type, description):
    """
    Ask OpenStack Keystone to create a service
    """
    api_cmd = api_url + "/services"
    req = json.dumps({"service": {
        "name": name,
        "type": type,
        "description": description}})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.Service(response)


def delete_service(token, api_url, id):
    """
    Ask OpenStack Keystone to delete a service
    """
    api_cmd = api_url + "/services/" + id
    response = rest_api_request(token, "DELETE", api_cmd)
    return keystone.Service(response)


def get_endpoints(token, api_url):
    """
    Ask OpenStack Keystone for a list of endpoints
    """
    api_cmd = api_url + "/endpoints"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.EndpointList(response)


def create_endpoint(token, api_url, service_id, region_name, type, url):
    """
    Ask OpenStack Keystone to create an endpoint
    """
    api_cmd = api_url + "/endpoints"
    req = json.dumps({"endpoint": {
        "region": region_name,
        "service_id": service_id,
        "interface": type,
        "url": url}})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.Endpoint(response)


def delete_endpoint(token, api_url, id):
    """
    Ask OpenStack Keystone to delete an endpoint
    """
    api_cmd = api_url + "/endpoints/" + id
    response = rest_api_request(token, "DELETE", api_cmd)
    return keystone.Endpoint(response)


def get_users(token, api_url):
    """
    Ask OpenStack Keystone for a list of users
    """
    api_cmd = api_url + "/users"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.UserList(response)


def create_user(token, api_url, name, password, email, project_id, domain_id):
    """
    Ask OpenStack Keystone to create a user
    """
    api_cmd = api_url + "/users"
    req = json.dumps({"user": {
        "password": password,
        "default_project_id": project_id,
        "domain_id": domain_id,
        "name": name,
        "email": email
    }})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.User(response)


def create_domain_user(token, api_url, name, password, email, domain_id):
    """
    Ask OpenStack Keystone to create a domain user
    """
    api_cmd = api_url + "/users"
    req = json.dumps({"user": {
        "password": password,
        "domain_id": domain_id,
        "name": name,
        "email": email
    }})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.User(response)


def delete_user(token, api_url, id):
    """
    Ask OpenStack Keystone to create a user
    """
    api_cmd = api_url + "/users/" + id
    response = rest_api_request(token, "DELETE", api_cmd)
    return keystone.User(response)


def add_role(token, api_url, project_id, user_id, role_id):
    """
    Ask OpenStack Keystone to add a role
    """
    api_cmd = "%s/projects/%s/users/%s/roles/%s" % (
              api_url, project_id, user_id, role_id)
    response = rest_api_request(token, "PUT", api_cmd)
    return keystone.Role(response)


def add_role_on_domain(token, api_url, domain_id, user_id, role_id):
    """
    Ask OpenStack Keystone to assign role to user on domain
    """
    api_cmd = "%s/domains/%s/users/%s/roles/%s" % (
              api_url, domain_id, user_id, role_id)
    response = rest_api_request(token, "PUT", api_cmd)
    return keystone.Role(response)


def get_roles(token, api_url):
    """
    Ask OpenStack Keystone for a list of roles
    """
    api_cmd = api_url + "/roles"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.RoleList(response)


def get_domains(token, api_url):
    """
    Ask OpenStack Keystone for a list of domains
    """
    # Domains are only available from the keystone V3 API
    api_cmd = api_url + "/domains"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.DomainList(response)


def create_domain(token, api_url, name, description):
    api_cmd = api_url + "/domains"
    req = json.dumps({"domain": {
        "enabled": True,
        "name": name,
        "description": description}})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.Domain(response)


def disable_domain(token, api_url, id):
    api_cmd = api_url + "/domains/" + id
    req = json.dumps({"domain": {
        "enabled": False}})
    response = rest_api_request(token, "PATCH", api_cmd, api_cmd_payload=req)
    return keystone.Domain(response)


def delete_domain(token, api_url, id):
    """
    Ask OpenStack Keystone to delete a project
    """
    api_cmd = api_url + "/domains/" + id
    response = rest_api_request(token, "DELETE", api_cmd,)
    return keystone.Domain(response)


def get_projects(token, api_url):
    """
    Ask OpenStack Keystone for a list of projects
    """
    api_cmd = api_url + "/projects"
    response = rest_api_request(token, "GET", api_cmd)
    return keystone.ProjectList(response)


def create_project(token, api_url, name, description, domain_id):
    """
    Ask OpenStack Keystone to create a project
    """
    api_cmd = api_url + "/projects"
    req = json.dumps({"project": {
        "enabled": True,
        "name": name,
        "domain_id": domain_id,
        "is_domain": False,
        "description": description}})
    response = rest_api_request(token, "POST", api_cmd, api_cmd_payload=req)
    return keystone.Project(response)


def delete_project(token, api_url, id):
    """
    Ask OpenStack Keystone to delete a project
    """
    api_cmd = api_url + "/projects/" + id
    response = rest_api_request(token, "DELETE", api_cmd,)
    return keystone.Project(response)
