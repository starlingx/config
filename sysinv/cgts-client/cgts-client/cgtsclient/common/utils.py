# Copyright 2013-2019 Wind River, Inc
# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
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

from __future__ import print_function
try:
    import tsconfig.tsconfig as tsc
    is_remote = False
except Exception:
    is_remote = True

import argparse
from collections import OrderedDict
import copy
import dateutil
import math
import os
import prettytable
import re
import six
import sys
import textwrap
import uuid
import yaml

from prettytable import ALL
from prettytable import FRAME
from prettytable import NONE

from datetime import datetime
from dateutil import parser
from functools import wraps

from cgtsclient import exc
from oslo_utils import importutils

from cgtsclient.common import wrapping_formatters
from six.moves import input


class HelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(HelpFormatter, self).start_section(heading)


# noinspection PyUnusedLocal
def _wrapping_formatter_callback_decorator(subparser, command, callback):
    """
        - Adds the --nowrap option to a CLI command.
          This option, when on, deactivates word wrapping.
        - Decorates the command's callback function in order to process
          the nowrap flag

        :param subparser:
        :return: decorated callback
        """

    try:
        subparser.add_argument('--nowrap', action='store_true',
                               help='No wordwrapping of output')
    except Exception as e:
        # exception happens when nowrap option already configured
        # for command - so get out with callback undecorated
        return callback

    def no_wrap_decorator_builder(callback):

        def process_callback_with_no_wrap(cc, args={}):
            no_wrap = args.nowrap
            # turn on/off wrapping formatters when outputting CLI results
            wrapping_formatters.set_no_wrap(no_wrap)
            return callback(cc, args=args)

        return process_callback_with_no_wrap

    decorated_callback = no_wrap_decorator_builder(callback)
    return decorated_callback


def _does_command_need_no_wrap(callback):
    if callback.__name__.startswith("do_") and \
       callback.__name__.endswith("_list"):
        return True

    if callback.__name__ in \
            ['donot_config_ntp_list',
             'donot_config_ptp_list',
             'do_host_apply_memprofile',
             'do_host_apply_cpuprofile',
             'do_host_apply_ifprofile',
             'do_host_apply_profile',
             'do_host_apply_storprofile',
             'donot_config_oam_list',
             'donot_dns_list',
             'do_host_cpu_modify',
             'do_event_suppress',
             'do_event_unsuppress',
             'do_event_unsuppress_all']:
        return True
    return False


def define_command(subparsers, command, callback, cmd_mapper):
    '''Define a command in the subparsers collection.

    :param subparsers: subparsers collection where the command will go
    :param command: command name
    :param callback: function that will be used to process the command
    '''
    desc = callback.__doc__ or ''
    help = desc.strip().split('\n')[0]
    arguments = getattr(callback, 'arguments', [])

    subparser = subparsers.add_parser(command, help=help,
                                      description=desc,
                                      add_help=False,
                                      formatter_class=HelpFormatter)
    subparser.add_argument('-h', '--help', action='help',
                           help=argparse.SUPPRESS)

    # Are we a list command?
    if _does_command_need_no_wrap(callback):
        # then decorate it with wrapping data formatter functionality
        func = _wrapping_formatter_callback_decorator(subparser, command, callback)
    else:
        func = callback

    cmd_mapper[command] = subparser
    for (args, kwargs) in arguments:
        subparser.add_argument(*args, **kwargs)
    subparser.set_defaults(func=func)


def define_commands_from_module(subparsers, command_module, cmd_mapper):
    '''Find all methods beginning with 'do_' in a module, and add them
    as commands into a subparsers collection.
    '''
    for method_name in (a for a in dir(command_module) if a.startswith('do_')):
        # Commands should be hypen-separated instead of underscores.
        command = method_name[3:].replace('_', '-')
        callback = getattr(command_module, method_name)
        define_command(subparsers, command, callback, cmd_mapper)


# Decorator for cli-args
def arg(*args, **kwargs):
    def _decorator(func):
        # Because of the sematics of decorator composition if we just append
        # to the options list positional options will appear to be backwards.
        func.__dict__.setdefault('arguments', []).insert(0, (args, kwargs))
        return func

    return _decorator


def prettytable_builder(field_names=None, **kwargs):
    return WRPrettyTable(field_names, **kwargs)


# noinspection PyUnusedLocal
def wordwrap_header(field, field_label, formatter):
    """
      Given a field label (the header text for one column) and the word wrapping formatter for a column,
      this function asks the formatter for the desired column width and then
      performs a wordwrap of field_label

    :param field:  the field name associated with the field_label
    :param field_label:  field_label to word wrap
    :param formatter: the field formatter
    :return: word wrapped field_label
    """
    if wrapping_formatters.is_nowrap_set():
        return field_label

    if not wrapping_formatters.WrapperFormatter.is_wrapper_formatter(formatter):
        return field_label
    # go to the column's formatter and ask it what the width should be
    wrapper_formatter = formatter.wrapper_formatter
    actual_width = wrapper_formatter.get_actual_column_char_len(wrapper_formatter.get_calculated_desired_width())
    # now word wrap based on column width
    wrapped_header = textwrap.fill(field_label, actual_width)
    return wrapped_header


def pretty_choice_list(l):
    return ', '.join("'%s'" % i for i in l)


def _sort_for_list(objs, fields, formatters={}, sortby=0, reversesort=False):

    # Sort only if necessary
    if sortby is None:
        return objs

    rows_to_sort = copy.deepcopy(objs)
    sort_field = fields[sortby]

    # figure out sort key function
    if sort_field in formatters:
        field_formatter = formatters[sort_field]
        if wrapping_formatters.WrapperFormatter.is_wrapper_formatter(field_formatter):
            sort_key = lambda o: field_formatter.wrapper_formatter.get_unwrapped_field_value(o)
        else:
            sort_key = lambda o: field_formatter(o)
    else:
        sort_key = lambda o: getattr(o, sort_field, '')

    rows_to_sort.sort(reverse=reversesort, key=sort_key)

    return rows_to_sort


def default_printer(s):
    print(s)


def pt_builder(field_labels, fields, formatters, paging, printer=default_printer):
    """
      returns an object that 'fronts' a prettyTable object
      that can handle paging as well as automatically falling back
      to not word wrapping when word wrapping does not cause the
      output to fit the terminal width.
    """

    class PT_Builder(object):

        def __init__(self, field_labels, fields, formatters, no_paging):
            self.objs_in_pt = []
            self.unwrapped_field_labels = field_labels
            self.fields = fields
            self.formatters = formatters
            self.header_height = 0
            self.terminal_width, self.terminal_height = get_terminal_size()
            self.terminal_lines_left = self.terminal_height
            self.paging = not no_paging
            self.paged_rows_added = 0
            self.pt = None
            self.quit = False

        def add_row(self, obj):
            if self.quit:
                return False
            if not self.pt:
                self.build_pretty_table()
            return self._row_add(obj)

        def __add_row_and_obj(self, row, obj):
            self.pt.add_row(row)
            self.objs_in_pt.append(obj)

        def _row_add(self, obj):

            row = _build_row_from_object(self.fields, self.formatters, obj)

            if not paging:
                self.__add_row_and_obj(row, obj)
                return True

            rheight = row_height(row)
            if (self.terminal_lines_left - rheight) >= 0 or self.paged_rows_added == 0:
                self.__add_row_and_obj(row, obj)
                self.terminal_lines_left -= rheight
            else:
                printer(self.get_string())
                if self.terminal_lines_left > 0:
                    printer("\n" * (self.terminal_lines_left - 1))

                s = input("Press Enter to continue or 'q' to exit...")
                if s == 'q':
                    self.quit = True
                    return False
                self.terminal_lines_left = self.terminal_height - self.header_height
                self.build_pretty_table()
                self.__add_row_and_obj(row, obj)
                self.terminal_lines_left -= rheight
            self.paged_rows_added += 1

        def get_string(self):
            if not self.pt:
                self.build_pretty_table()
            objs = copy.copy(self.objs_in_pt)
            self.objs_in_pt = []
            output = self.pt.get_string()
            if wrapping_formatters.is_nowrap_set():
                return output
            output_width = wrapping_formatters._get_width(output)
            if output_width <= self.terminal_width:
                return output
            # At this point pretty Table (self.pt) does not fit the terminal width so let's
            # temporarily turn wrapping off, rebuild the pretty Table with the data unwrapped.
            orig_no_wrap_settings = wrapping_formatters.set_no_wrap_on_formatters(True, self.formatters)
            self.build_pretty_table()
            for o in objs:
                self.add_row(o)
            wrapping_formatters.unset_no_wrap_on_formatters(orig_no_wrap_settings)
            return self.pt.get_string()

        def build_pretty_table(self):
            field_labels = [wordwrap_header(field, field_label, formatter)
                            for field, field_label, formatter in
                            zip(self.fields, self.unwrapped_field_labels, [formatters.get(f, None)
                                                                           for f in self.fields])]
            self.pt = prettytable_builder(field_labels, caching=False, print_empty=False)
            self.pt.align = 'l'
            # 2 header border lines + 1 bottom border + 1 prompt + header data height
            self.header_height = 2 + 1 + 1 + row_height(field_labels)
            self.terminal_lines_left = self.terminal_height - self.header_height
            return self.pt

        def done(self):
            if self.quit:
                return

            if not self.paging or (self.terminal_lines_left < self.terminal_height - self.header_height):
                printer(self.get_string())

    return PT_Builder(field_labels, fields, formatters, not paging)


def parse_date(string_data):
    """Parses a date-like input string into a timezone aware Python
    datetime.
    """

    if not isinstance(string_data, six.string_types):
        return string_data

    pattern = r'(\d{4}-\d{2}-\d{2}[T ])?\d{2}:\d{2}:\d{2}(\.\d{6})?Z?'

    def convert_date(matchobj):
        formats = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f",
                   "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                   "%Y-%m-%dT%H:%M:%SZ"]
        datestring = matchobj.group(0)
        if datestring:
            for format in formats:
                try:
                    datetime.strptime(datestring, format)
                    datestring += "+0000"
                    parsed = parser.parse(datestring)
                    converted = parsed.astimezone(dateutil.tz.tzlocal())
                    converted = datetime.strftime(converted, format)
                    return converted
                except Exception:
                    pass
        return datestring

    return re.sub(pattern, convert_date, string_data)


def print_list(objs, fields, field_labels, formatters={}, sortby=0,
               reversesort=False, no_wrap_fields=[], printer=default_printer,
               output_format=None):

    if output_format == 'yaml' or output_format == 'value':
        my_dict_list = []
        for o in objs:
            my_dict_list.append(dict((k, getattr(o, k)) for k in fields))

        if output_format == 'yaml':
            print(yaml.safe_dump(my_dict_list, default_flow_style=False))

        elif output_format == 'value':
            for _dict in my_dict_list:
                print_dict_value(_dict)

    else:
        return print_long_list(objs, fields, field_labels, formatters=formatters, sortby=sortby,
                               reversesort=reversesort, no_wrap_fields=no_wrap_fields,
                               no_paging=True, printer=printer)


def _build_row_from_object(fields, formatters, o):
    """
      takes an object o and converts to an array of values
      compatible with the input for prettyTable.add_row(row)
    """
    row = []
    for field in fields:
        if field in formatters:
            data = parse_date(getattr(o, field, ''))
            setattr(o, field, data)
            data = formatters[field](o)
            row.append(data)
        else:
            data = parse_date(getattr(o, field, ''))
            row.append(data)
    return row


def print_tuple_list(tuples, tuple_labels=[], formatters={}):
    pt = prettytable.PrettyTable(['Property', 'Value'],
                                 caching=False, print_empty=False)
    pt.align = 'l'

    if not tuple_labels:
        for t in tuples:
            if len(t) == 2:
                f, v = t
                v = parse_date(v)
                if f in formatters:
                    v = formatters[f](v)
                pt.add_row([f, v])
    else:
        for t, l in zip(tuples, tuple_labels):
            if len(t) == 2:
                f, v = t
                v = parse_date(v)
                if f in formatters:
                    v = formatters[f](v)
                pt.add_row([l, v])

    print(pt.get_string())


def str_height(text):
    if not text:
        return 1
    lines = str(text).split("\n")
    height = len(lines)
    return height


def row_height(texts):
    if not texts or len(texts) == 0:
        return 1
    height = max(str_height(text) for text in texts)
    return height


def print_long_list(objs, fields, field_labels, formatters={}, sortby=0, reversesort=False, no_wrap_fields=[],
                    no_paging=False, printer=default_printer):

    formatters = wrapping_formatters.as_wrapping_formatters(objs, fields, field_labels, formatters,
                                                            no_wrap_fields=no_wrap_fields)

    objs = _sort_for_list(objs, fields, formatters=formatters, sortby=sortby, reversesort=reversesort)

    pt = pt_builder(field_labels, fields, formatters, not no_paging, printer=printer)

    for o in objs:
        pt.add_row(o)

    pt.done()


def print_dict_with_format(data, wrap=0, output_format=None):
    if output_format == 'yaml':
        print(yaml.safe_dump(data, default_flow_style=False))

    elif output_format == 'value':
        print_dict_value(data)

    else:
        ordereddata = OrderedDict(sorted(data.items(), key=lambda t: t[0]))
        print_dict(ordereddata, wrap=wrap)


def print_dict_value(d):
    # Print values on a single line separated by spaces
    # e.g. 'available ntp'
    print(' '.join(map(str, d.values())))


def print_dict(d, dict_property="Property", wrap=0):
    pt = prettytable.PrettyTable([dict_property, 'Value'],
                                 caching=False, print_empty=False)
    pt.align = 'l'
    for k, v in sorted(d.items()):
        v = parse_date(v)
        # convert dict to str to check length
        if isinstance(v, dict):
            v = str(v)
        if wrap > 0:
            v = textwrap.fill(six.text_type(v), wrap)
        # if value has a newline, add in multiple rows
        # e.g. fault with stacktrace
        if v and isinstance(v, six.string_types) and r'\n' in v:
            lines = v.strip().split(r'\n')
            col1 = k
            for line in lines:
                pt.add_row([col1, line])
                col1 = ''
        else:
            pt.add_row([k, v])
    print(pt.get_string())


def find_resource(manager, name_or_id):
    """Helper for the _find_* methods."""
    # first try to get entity as integer id
    try:
        if isinstance(name_or_id, int) or name_or_id.isdigit():
            return manager.get(int(name_or_id))
    except exc.NotFound:
        pass

    # now try to get entity as uuid
    try:
        uuid.UUID(str(name_or_id))
        return manager.get(name_or_id)
    except (ValueError, exc.NotFound):
        pass

    # finally try to find entity by name
    try:
        return manager.find(name=name_or_id)
    except exc.NotFound:
        msg = "No %s with a name or ID of '%s' exists." % \
              (manager.resource_class.__name__.lower(), name_or_id)
        raise exc.CommandError(msg)


def string_to_bool(arg):
    return arg.strip().lower() in ('t', 'true', 'yes', '1')


def env(*vars, **kwargs):
    """Search for the first defined of possibly many env vars

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.
    """
    for v in vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')


def import_versioned_module(version, submodule=None):
    module = 'cgtsclient.v%s' % version
    if submodule:
        module = '.'.join((module, submodule))
    return importutils.import_module(module)


def args_array_to_dict(kwargs, key_to_convert):
    values_to_convert = kwargs.get(key_to_convert)
    if values_to_convert:
        try:
            kwargs[key_to_convert] = dict(v.split("=", 1)
                                          for v in values_to_convert)
        except ValueError:
            raise exc.CommandError('%s must be a list of KEY=VALUE not "%s"' %
                                   (key_to_convert, values_to_convert))
    return kwargs


def args_array_to_patch(op, attributes):
    patch = []
    for attr in attributes:
        # Sanitize
        if not attr.startswith('/'):
            attr = '/' + attr

        if op in ['add', 'replace']:
            try:
                path, value = attr.split("=", 1)
                patch.append({'op': op, 'path': path, 'value': value})
            except ValueError:
                raise exc.CommandError('Attributes must be a list of '
                                       'PATH=VALUE not "%s"' % attr)
        elif op == "remove":
            # For remove only the key is needed
            patch.append({'op': op, 'path': attr})
        else:
            raise exc.CommandError('Unknown PATCH operation: %s' % op)
    return patch


def dict_to_patch(values, op='replace'):
    patch = []
    for key, value in values.items():
        path = '/' + key
        patch.append({'op': op, 'path': path, 'value': value})
    return patch


def exit(msg=''):
    if msg:
        print(msg, file=sys.stderr)
    sys.exit(1)


def objectify(func):
    """Mimic an object given a dictionary.

    Given a dictionary, create an object and make sure that each of its
    keys are accessible via attributes.
    Ignore everything if the given value is not a dictionary.
    :param func: A dictionary or another kind of object.
    :returns: Either the created object or the given value.

    >>> obj = {'old_key': 'old_value'}
    >>> oobj = objectify(obj)
    >>> oobj['new_key'] = 'new_value'
    >>> print oobj['old_key'], oobj['new_key'], oobj.old_key, oobj.new_key

    >>> @objectify
    ... def func():
         ...     return {'old_key': 'old_value'}
    >>> obj = func()
    >>> obj['new_key'] = 'new_value'
    >>> print obj['old_key'], obj['new_key'], obj.old_key, obj.new_key


    """

    def create_object(value):
        if isinstance(value, dict):
            # Build a simple generic object.
            class Object(dict):
                def __setitem__(self, key, val):
                    setattr(self, key, val)
                    return super(Object, self).__setitem__(key, val)

            # Create that simple generic object.
            ret_obj = Object()
            # Assign the attributes given the dictionary keys.
            for key, val in value.items():
                ret_obj[key] = val
                setattr(ret_obj, key, val)
            return ret_obj
        else:
            return value

    # If func is a function, wrap around and act like a decorator.
    if hasattr(func, '__call__'):
        @wraps(func)
        def wrapper(*args, **kwargs):
            """Wrapper function for the decorator.

            :returns: The return value of the decorated function.

            """
            value = func(*args, **kwargs)
            return create_object(value)

        return wrapper

    # Else just try to objectify the value given.
    else:
        return create_object(func)


def is_uuid_like(val):
    """Returns validation of a value as a UUID.

    For our purposes, a UUID is canonical form string:
    aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa

    """
    try:
        return str(uuid.UUID(val)) == val
    except (TypeError, ValueError, AttributeError):
        return False


def get_terminal_size():
    """Returns a tuple (x, y) representing the width(x) and the height(x)
    in characters of the terminal window.
    """

    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import struct
            import termios
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
                                                 '1234'))
        except Exception:
            return None
        if cr == (0, 0):
            return None
        if cr == (0, 0):
            return None
        return cr

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except Exception:
            pass
    if not cr:
        cr = (os.environ.get('LINES', 25), os.environ.get('COLUMNS', 80))
    return int(cr[1]), int(cr[0])


def normalize_field_data(obj, fields):
    for f in fields:
        if hasattr(obj, f):
            data = getattr(obj, f, '')
            try:
                data = str(data)
            except UnicodeEncodeError:
                setattr(obj, f, data.encode('utf-8'))


class WRPrettyTable(prettytable.PrettyTable):
    """A PrettyTable that allows word wrapping of its headers."""

    def __init__(self, field_names=None, **kwargs):
        super(WRPrettyTable, self).__init__(field_names, **kwargs)

    def _stringify_header(self, options):
        """
          This overridden version of _stringify_header can wrap its
          header data.  It leverages the functionality in  _stringify_row
          to perform this task.
          :returns string of header, including border text
        """
        bits = []
        if options["border"]:
            if options["hrules"] in (ALL, FRAME):
                bits.append(self._hrule)
                bits.append("\n")
        # For tables with no data or field names
        if not self._field_names:
            if options["vrules"] in (ALL, FRAME):
                bits.append(options["vertical_char"])
                bits.append(options["vertical_char"])
            else:
                bits.append(" ")
                bits.append(" ")

        header_row_data = []
        for field in self._field_names:
            if options["fields"] and field not in options["fields"]:
                continue
            if self._header_style == "cap":
                fieldname = field.capitalize()
            elif self._header_style == "title":
                fieldname = field.title()
            elif self._header_style == "upper":
                fieldname = field.upper()
            elif self._header_style == "lower":
                fieldname = field.lower()
            else:
                fieldname = field
            header_row_data.append(fieldname)

        # output actual header row data, word wrap when necessary
        bits.append(self._stringify_row(header_row_data, options))

        if options["border"] and options["hrules"] != NONE:
            bits.append("\n")
            bits.append(self._hrule)

        return "".join(bits)


def extract_keypairs(args):
    attributes = {}
    for parms in args.attributes:
        for parm in parms:
            # Check that there is a '='
            if parm.find('=') > -1:
                (key, value) = parm.split('=', 1)
            else:
                key = parm
                value = None

            attributes[key] = value
    return attributes


def size_unit_conversion(size, step):
    """
      This function converts size from a smaller unit (e.g. KiB)
      to a larger unit (e.g. GiB).

      :param size: Size value to convert from one unit to another
      :param step: Power of 2^10. e.g. From Byte to MiB is 2 steps.
                   From MiB to GiB is 1 step.
      :returns: The return value is a float with 3 digits after
                the decimal point.
    """
    return math.floor(float(size) / (1024 ** step) * 1000) / 1000.0


def _get_system_info(cc):
    """Gets the system mode and type"""
    if is_remote:
        system_info = cc.isystem.list()[0]
        return system_info.system_type, system_info.system_mode
    else:
        return tsc.system_type, tsc.system_mode
