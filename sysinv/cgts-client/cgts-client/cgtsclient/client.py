#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from keystoneauth1 import loading
from oslo_utils import importutils
from six.moves.urllib.parse import urlparse

from cgtsclient._i18n import _
from cgtsclient import exc


SERVICE_NAME = 'sysinv'
SERVICE_TYPE = 'platform'

PLATFORM_CONF_FILE = '/etc/platform/platform.conf'

# TODO(jvazhapp): Modify for dynamic lookup of the endpoints from a service
# rather than hard coding interfaces & ports
SYSINV_PORT_MAP = {
    'SystemController': {'admin': '26386', 'internal': '26385', 'public': '26385'},
    'RegionOne': {'admin': '6386', 'internal': '6385', 'public': '6385'},
    'Default': {'admin': '6385', 'internal': '6385', 'public': '6385'},
}

# Cache for distributed cloud role to avoid repeated file reads
_dc_role_cache = None


def _make_session(**kwargs):
    """Construct a session based on authentication information

    :param kwargs: keyword args containing credentials, either:
        * os_auth_token: pre-existing token to re-use
        * system_url: system API endpoint
        or:
        * os_username: name of user
        * os_password: user's password
        * os_auth_url: endpoint to authenticate against
        * insecure: allow insecure SSL (no cert verification)
        * os_tenant_{name|id}: name or ID of tenant
        * os_region_name: region of the service
        * os_project_name: name of a project
        * os_project_id: ID of a project
        * os_user_domain_name: name of a domain the user belongs to
        * os_user_domain_id: ID of a domain the user belongs to
        * os_project_domain_name: name of a domain the project belongs to
        * os_project_domain_id: ID of a domain the project belongs to
        * timeout: request timeout (in seconds)
        * ca_file: trusted CA file
        * cert_file: client certificate file
        * key_file: client key file
    """
    session = None
    if (kwargs.get('os_username') and
        kwargs.get('os_password') and
        kwargs.get('os_auth_url') and
        (kwargs.get('os_project_id') or
         kwargs.get('os_project_name'))):
        auth_kwargs = {}
        auth_url = kwargs.get('os_auth_url')
        project_id = kwargs.get('os_project_id')
        project_name = kwargs.get('os_project_name')
        user_domain_id = kwargs.get('os_user_domain_id')
        user_domain_name = kwargs.get('os_user_domain_name') or "Default"
        project_domain_id = kwargs.get('os_project_domain_id')
        project_domain_name = kwargs.get('os_project_domain_name') or "Default"
        # todo(abailey): we can enhance this to also support token
        auth_type = 'password'
        username = kwargs.get('os_username')
        password = kwargs.get('os_password')
        auth_kwargs.update({
            'auth_url': auth_url,
            'project_id': project_id,
            'project_name': project_name,
            'user_domain_id': user_domain_id,
            'user_domain_name': user_domain_name,
            'project_domain_id': project_domain_id,
            'project_domain_name': project_domain_name,
            'username': username,
            'password': password
        })

        # construct the appropriate session
        timeout = kwargs.get('timeout')
        insecure = kwargs.get('insecure')
        cacert = kwargs.get('ca_file')
        cert = kwargs.get('cert_file')
        key = kwargs.get('key_file')

        loader = loading.get_plugin_loader(auth_type)
        auth_plugin = loader.load_from_options(**auth_kwargs)
        session = loading.session.Session().load_from_options(auth=auth_plugin,
                                                              timeout=timeout,
                                                              insecure=insecure,
                                                              cacert=cacert,
                                                              cert=cert,
                                                              key=key)
    # session could still be None
    return session


def get_client(api_version, session=None, service_type=SERVICE_TYPE, **kwargs):
    """Get an authenticated client, based on credentials in the keyword args.

    :param api_version: the API version to use ('1' or '2')
    :param session: the session to use (if it exists)
    :param service_type: service_type should always be 'platform'
    :param kwargs: additional keyword args to pass to the client or auth
    """

    endpoint = kwargs.get('system_url')

    if kwargs.get('stx_auth_type') == 'oidc':
        _validate_oidc_params(**kwargs)
        endpoint = _build_oidc_endpoint(api_version, **kwargs)
        cli_kwargs = _build_oidc_cli_kwargs(**kwargs)
        session = None
        return Client(api_version, endpoint, session, **cli_kwargs)

    if endpoint:
        api_version_str = 'v' + api_version
        if api_version_str not in endpoint.split('/'):
            endpoint += '/' + api_version_str

    auth_token = kwargs.get('os_auth_token')
    # if we have an endpoint and token, use those
    if endpoint and auth_token:
        pass
    elif not session:
        # Make a session to determine the endpoint
        session = _make_session(**kwargs)

    if not endpoint:
        exception_msg = _('Must provide Keystone credentials or '
                          'user-defined endpoint and token')
        if session:
            try:
                # todo(abailey): add support for non 'os_' keys
                interface = kwargs.get('os_endpoint_type')
                region_name = kwargs.get('os_region_name')
                endpoint = session.get_endpoint(service_type=service_type,
                                                interface=interface,
                                                region_name=region_name)
            except Exception as e:
                raise exc.EndpointException(
                    _('%(message)s, error was: %(error)s') %
                    {'message': exception_msg, 'error': e})
        else:
            raise exc.AmbigiousAuthSystem(exception_msg)

    if session:
        # this will be a LegacyJsonAdapter
        cli_kwargs = {
            'session': session,
            'service_type': service_type,
            'service_name': SERVICE_NAME,
            'interface': kwargs.get('os_endpoint_type'),
            'region_name': kwargs.get('os_region_name'),
            'endpoint_override': endpoint,
            'global_request_id': kwargs.get('global_request_id'),
            'user_agent': kwargs.get('user_agent', 'cgtsclient'),
            'insecure': kwargs.get('insecure'),
            'ca_file': kwargs.get('ca_file'),
            'cert_file': kwargs.get('cert_file'),
            'key_file': kwargs.get('key_file')
        }
    else:
        # This will become a httplib2 object
        auth_ref = None
        cli_kwargs = {
            'token': auth_token,
            'insecure': kwargs.get('insecure'),
            'cacert': kwargs.get('cacert'),
            'timeout': kwargs.get('timeout'),
            'ca_file': kwargs.get('ca_file'),
            'cert_file': kwargs.get('cert_file'),
            'key_file': kwargs.get('key_file'),
            'auth_ref': auth_ref,
            'auth_url': kwargs.get('os_auth_url'),
        }
    return Client(api_version, endpoint, session, **cli_kwargs)


def _build_oidc_endpoint(api_version, **kwargs):
    """Build OIDC endpoint URL from configuration."""
    interface = _normalize_interface(kwargs.get('os_endpoint_type'))
    protocol = _get_protocol(interface)

    auth_url = kwargs.get('os_auth_url')
    if not auth_url:
        raise exc.InvalidEndpoint(_('os_auth_url is required'))

    addr_parts = urlparse(auth_url)
    hostname = addr_parts.hostname
    if not hostname:
        raise exc.InvalidEndpoint(_('Invalid os_auth_url: missing hostname'))
    if ':' in hostname and not hostname.startswith('['):
        hostname = f"[{hostname}]"

    region_name = kwargs.get('os_region_name', 'Default')
    port_map = kwargs.get('port_map', SYSINV_PORT_MAP)
    region_ports = port_map.get(region_name, port_map.get('Default', {}))
    port = region_ports.get(interface)

    if not port:
        raise exc.InvalidEndpoint(_('No port for region %s interface %s') % (region_name, interface))

    return f"{protocol}://{hostname}:{port}/v{api_version}"


def _normalize_interface(interface):
    """Normalize interface type to standard values."""
    interface_map = {
        'publicURL': 'public',
        'internalURL': 'internal',
        'adminURL': 'admin'
    }
    normalized = interface_map.get(interface, interface)
    return normalized if normalized in ('public', 'internal', 'admin') else 'public'


def _get_dc_role():
    """Get distributed cloud role with caching."""
    global _dc_role_cache
    if _dc_role_cache is None:
        try:
            with open(PLATFORM_CONF_FILE, 'r') as f:
                for line in f:
                    if line.startswith('distributed_cloud_role='):
                        role = line.split('=')[1].strip()
                        _dc_role_cache = role in ['subcloud', 'systemcontroller']
                        return _dc_role_cache
        except FileNotFoundError:
            pass  # Non-DC systems may not have distributed_cloud_role
        except Exception as e:
            print("Error reading %s: %s", PLATFORM_CONF_FILE, e)

        _dc_role_cache = False
    return _dc_role_cache


def _get_protocol(interface):
    is_dc = _get_dc_role()
    if not is_dc:
        protocol = 'https' if interface == 'public' else 'http'
    else:
        protocol = 'https' if interface in ('public', 'admin') else 'http'
    return protocol


def _validate_oidc_params(**kwargs):
    """Validate required OIDC parameters."""
    required_params = ['os_auth_url', 'os_username']
    missing = [p for p in required_params if not kwargs.get(p)]
    if missing:
        raise exc.InvalidEndpoint(_('Missing required OIDC parameters: %s') % ', '.join(missing))


def _build_oidc_cli_kwargs(**kwargs):
    """Build CLI kwargs for OIDC authentication."""
    return {
        'insecure': kwargs.get('insecure'),
        'cacert': kwargs.get('cacert'),
        'timeout': kwargs.get('timeout'),
        'ca_file': kwargs.get('ca_file'),
        'cert_file': kwargs.get('cert_file'),
        'key_file': kwargs.get('key_file'),
        'auth_ref': None,
        'auth_url': kwargs.get('os_auth_url'),
        'oidc_auth': bool(kwargs.get('stx_auth_type') == 'oidc'),
        'oidc_username': kwargs.get('os_username'),
    }


def Client(version, *args, **kwargs):
    module = importutils.import_versioned_module('cgtsclient',
                                                 version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(*args, **kwargs)
