#    Copyright 2013 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#


"""Utility methods for objects"""

import ast
import datetime
import iso8601
import netaddr
import uuid
import six

from oslo_utils import timeutils
from sysinv._i18n import _
from sysinv.common import constants


def datetime_or_none(dt):
    """Validate a datetime or None value."""
    if dt is None:
        return None
    elif isinstance(dt, datetime.datetime):
        if dt.utcoffset() is None:
            # NOTE(danms): Legacy objects from sqlalchemy are stored in UTC,
            # but are returned without a timezone attached.
            # As a transitional aid, assume a tz-naive object is in UTC.
            return dt.replace(tzinfo=iso8601.UTC)
        else:
            return dt
    raise ValueError('A datetime.datetime is required here')


def datetime_or_str_or_none(val):
    if isinstance(val, six.string_types):
        return timeutils.parse_isotime(val)
    return datetime_or_none(val)


def bool_or_none(val):
    """Attempt to parse an boolean value, or None."""
    if val is None:
        return False
    elif isinstance(val, six.string_types):
        return bool(val.lower() in ['y', 'n', 'yes', 'no', 'true', 'false'])
    else:
        return bool(int(val) != 0)


def int_or_none(val):
    """Attempt to parse an integer value, or None."""
    if val is None:
        return val
    else:
        return int(val)


def float_or_none(val):
    """Attempt to parse a float value, or None."""
    if val is None:
        return val
    else:
        return float(val)


def int_or_zero(val):
    """Attempt to parse an integer value, if None return zero."""
    if val is None:
        return int(0)
    else:
        return int(val)


def str_or_none(val):
    """Attempt to stringify a value, or None."""
    if val is None:
        return val
    else:
        return six.text_type(val)


def list_of_strings_or_none(val):
    if val is None:
        return val
    if not isinstance(val, list):
        raise ValueError(_('A list of strings is required here'))
    if not all([isinstance(x, six.string_types) for x in val]):
        raise ValueError(_('Invalid values %s found in list (strings are required)') % val)
    return val


def dict_or_none(val):
    """Attempt to dictify a value, or None."""
    if val is None:
        return {}
    elif isinstance(val, str):
        return dict(ast.literal_eval(val))
    else:
        try:
            return dict(val)
        except ValueError:
            return {}


def uuid_or_none(val):
    """Attempt to dictify a value, or None."""
    if val is None:
        return None
    elif isinstance(val, six.string_types):
        return str(uuid.UUID(val.strip()))
    raise ValueError(_('Invalid UUID value %s') % val)


def ipv4_mode_or_none(val):
    """Attempt to validate an IPv4 address mode."""
    if val is None:
        return None
    elif not isinstance(val, six.string_types):
        raise ValueError(_('Invalid IPv4 address mode %s') % val)
    elif val not in constants.IPV4_ADDRESS_MODES:
        raise ValueError(_('Unsupported IPv4 address mode %s') % val)
    return val


def ipv6_mode_or_none(val):
    """Attempt to validate an IPv4 address mode."""
    if val is None:
        return None
    elif not isinstance(val, six.string_types):
        raise ValueError(_('Invalid IPv6 address mode %s') % val)
    elif val not in constants.IPV6_ADDRESS_MODES:
        raise ValueError(_('Unsupported IPv6 address mode %s') % val)
    return val


def ip_str_or_none(version=None):
    """Return a IP address string representation validator."""
    def validator(val, version=version):
        if val is None:
            return val
        else:
            return str(netaddr.IPAddress(val, version=version))
    return validator


def ip_or_none(version=None):
    """Return a version-specific IP address validator."""
    def validator(val, version=version):
        if val is None:
            return val
        else:
            return netaddr.IPAddress(val, version=version)
    return validator


def nested_object_or_none(objclass):
    def validator(val, objclass=objclass):
        if val is None or isinstance(val, objclass):
            return val
        raise ValueError('An object of class %s is required here' % objclass)
    return validator


def dt_serializer(name):
    """Return a datetime serializer for a named attribute."""
    def serializer(self, name=name):
        if getattr(self, name) is not None:
            return timeutils.isotime(getattr(self, name))
        else:
            return None
    return serializer


def dt_deserializer(instance, val):
    """A deserializer method for datetime attributes."""
    if val is None:
        return None
    else:
        return timeutils.parse_isotime(val)


def obj_serializer(name):
    def serializer(self, name=name):
        if getattr(self, name) is not None:
            return getattr(self, name).obj_to_primitive()
        else:
            return None
    return serializer
