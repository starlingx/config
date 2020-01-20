#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Manages WrapperFormatter objects.

WrapperFormatter objects can be used for wrapping CLI column celldata in order
for the CLI table (using prettyTable) to fit the terminal screen

The basic idea is:

   Once celldata is retrieved and ready to display, first iterate through the celldata
   and word wrap it so that fits programmer desired column widths.  The
   WrapperFormatter objects fill this role.

   Once the celldata is formatted to their desired widths, then it can be passed to
   the existing prettyTable code base for rendering.

"""
import copy
import re
import six
import textwrap

from cgtsclient.common.cli_no_wrap import is_nowrap_set
from cgtsclient.common.cli_no_wrap import set_no_wrap
from prettytable import _get_size

UUID_MIN_LENGTH = 36

# monkey patch (customize) how the textwrap module breaks text into chunks
wordsep_re = re.compile(r'(\s+|'                          # any whitespace
                        r',|'
                        r'=|'
                        r'\.|'
                        r':|'
                        r'[^\s\w]*\w+[^0-9\W]-(?=\w+[^0-9\W])|'   # hyphenated words
                        r'(?<=[\w\!\"\'\&\.\,\?])-{2,}(?=\w))')   # em-dash

textwrap.TextWrapper.wordsep_re = wordsep_re


def _get_width(value):
    if value is None:
        return 0
    # TODO(jkung): take into account \n
    return _get_size(six.text_type(value))[0]  # get width from [width,height]


def _get_terminal_width():
    from cgtsclient.common.utils import get_terminal_size
    result = get_terminal_size()[0]
    return result


def is_uuid_field(field_name):
    """
    :param field_name:
    :return: True if field_name looks like a uuid name
    """
    if field_name is not None and field_name in ["uuid", "UUID"] or field_name.endswith("uuid"):
        return True
    return False


class WrapperContext(object):
    """Context for the wrapper formatters

       Maintains a list of the current WrapperFormatters
       being used to format the prettyTable celldata

       Allows wrappers access to its 'sibling' wrappers
       contains convenience methods and attributes
       for calculating current tableWidth.
    """

    def __init__(self):
        self.wrappers = []
        self.wrappers_by_field = {}
        self.non_data_chrs_used_by_table = 0
        self.num_columns = 0
        self.terminal_width = -1

    def set_num_columns(self, num_columns):
        self.num_columns = num_columns
        self.non_data_chrs_used_by_table = (num_columns * 3) + 1

    def add_column_formatter(self, field, wrapper):
        self.wrappers.append(wrapper)
        self.wrappers_by_field[field] = wrapper

    def get_terminal_width(self):
        if self.terminal_width == -1:
            self.terminal_width = _get_terminal_width()
        return self.terminal_width

    def get_table_width(self):
        """
          Calculates table width by looping through all
          column formatters and summing up their widths
        :return: total table width
        """
        widths = [w.get_actual_column_char_len(w.get_calculated_desired_width(), check_remaining_row_chars=False) for w
                  in
                  self.wrappers]
        chars_used_by_data = sum(widths)
        width = self.non_data_chrs_used_by_table + chars_used_by_data
        return width

    def is_table_too_wide(self):
        """
        :return: True if calculated table width is too wide for the terminal width
        """
        if self.get_terminal_width() < self.get_table_width():
            return True
        return False


def field_value_function_factory(formatter, field):
    """Builds function for getting a field value from table cell celldata
       As a side-effect, attaches function as the 'get_field_value' attribute
       of the formatter
    :param formatter:the formatter to attach return function to
    :param field:
    :return: function that returns cell celldata
    """

    def field_value_function_builder(data):
        if isinstance(data, dict):
            formatter.get_field_value = lambda celldata: celldata.get(field, None)
        else:
            formatter.get_field_value = lambda celldata: getattr(celldata, field)
        return formatter.get_field_value(data)

    return field_value_function_builder


class WrapperFormatter(object):
    """Base (abstract) class definition of wrapping formatters"""

    def __init__(self, ctx, field):
        self.ctx = ctx
        self.add_blank_line = False
        self.no_wrap = False
        self.min_width = 0
        self.field = field
        self.header_width = 0
        self.actual_column_char_len = -1
        self.textWrapper = None

        if self.field:
            self.get_field_value = field_value_function_factory(self, field)
        else:
            self.get_field_value = lambda data: data

    def get_basic_desired_width(self):
        return self.min_width

    def get_calculated_desired_width(self):
        basic_desired_width = self.get_basic_desired_width()
        if self.header_width > basic_desired_width:
            return self.header_width
        return basic_desired_width

    def get_sibling_wrappers(self):
        """
        :return: a list of your sibling wrappers for the other fields
        """
        others = [w for w in self.ctx.wrappers if w != self]
        return others

    def get_remaining_row_chars(self):
        used = [w.get_actual_column_char_len(w.get_calculated_desired_width(),
                                             check_remaining_row_chars=False)
                for w in self.get_sibling_wrappers()]
        chrs_used_by_data = sum(used)
        remaining_chrs_in_row = (self.ctx.get_terminal_width() -
                                 self.ctx.non_data_chrs_used_by_table) - chrs_used_by_data
        return remaining_chrs_in_row

    def set_min_width(self, min_width):
        self.min_width = min_width

    def set_actual_column_len(self, actual):
        self.actual_column_char_len = actual

    def get_actual_column_char_len(self, desired_char_len, check_remaining_row_chars=True):
        """Utility method to adjust desired width to a width
           that can actually be applied based on current table width
           and current terminal width

           Will not allow actual width to be less than min_width
           min_width is typically length of the column header text
           or the longest 'word' in the celldata

        :param desired_char_len:
        :param check_remaining_row_chars:
        :return:
        """
        if self.actual_column_char_len != -1:
            return self.actual_column_char_len  # already calculated
        if desired_char_len < self.min_width:
            actual = self.min_width
        else:
            actual = desired_char_len
        if check_remaining_row_chars and actual > self.min_width:
            remaining = self.get_remaining_row_chars()
            if actual > remaining >= self.min_width:
                actual = remaining
        if check_remaining_row_chars:
            self.set_actual_column_len(actual)
            if self.ctx.is_table_too_wide():
                # Table too big can I shrink myself?
                if actual > self.min_width:
                    # shrink column
                    while actual > self.min_width:
                        actual -= 1  # TODO(jkung): fix in next sprint
                        #  each column needs to share in
                        # table shrinking - but this is good
                        # enough for now - also - why the loop?
                    self.set_actual_column_len(actual)

        return actual

    def _textwrap_fill(self, s, actual_width):
        if not self.textWrapper:
            self.textWrapper = textwrap.TextWrapper(actual_width)
        else:
            self.textWrapper.width = actual_width
        return self.textWrapper.fill(s)

    def text_wrap(self, s, width):
        """
          performs actual text wrap
        :param s:
        :param width:  in characters
        :return: formatted text
        """
        if self.no_wrap:
            return s
        actual_width = self.get_actual_column_char_len(width)
        new_s = self._textwrap_fill(s, actual_width)
        wrapped = new_s != s
        if self.add_blank_line and wrapped:
            new_s += "\n".ljust(actual_width)
        return new_s

    def format(self, data):
        return str(self.get_field_value(data))

    def get_unwrapped_field_value(self, data):
        return self.get_field_value(data)

    def as_function(self):
        def foo(data):
            return self.format(data)

        foo.WrapperFormatterMarker = True
        foo.wrapper_formatter = self
        return foo

    @staticmethod
    def is_wrapper_formatter(foo):
        if not foo:
            return False
        return getattr(foo, "WrapperFormatterMarker", False)


class WrapperLambdaFormatter(WrapperFormatter):
    """A wrapper formatter that adapts a function (callable)
       to look like a WrapperFormatter
    """

    def __init__(self, ctx, field, format_function):
        super(WrapperLambdaFormatter, self).__init__(ctx, field)
        self.format_function = format_function

    def format(self, data):
        return self.format_function(self.get_field_value(data))


class WrapperFixedWidthFormatter(WrapperLambdaFormatter):
    """A wrapper formatter that forces the text to wrap within
       a specific width (in chars)
    """

    def __init__(self, ctx, field, width):
        super(WrapperFixedWidthFormatter, self).__init__(ctx, field,
                                                         lambda data:
                                                         self.text_wrap(str(data),
                                                                        self.get_calculated_desired_width()))
        self.width = width

    def get_basic_desired_width(self):
        return self.width


class WrapperPercentWidthFormatter(WrapperFormatter):
    """A wrapper formatter that forces the text to wrap within
       a specific percentage width of the current terminal width
    """

    def __init__(self, ctx, field, width_as_decimal):
        super(WrapperPercentWidthFormatter, self).__init__(ctx, field)
        self.width_as_decimal = width_as_decimal

    def get_basic_desired_width(self):
        width = int((self.ctx.get_terminal_width() - self.ctx.non_data_chrs_used_by_table) *
                    self.width_as_decimal)
        return width

    def format(self, data):
        width = self.get_calculated_desired_width()
        field_value = self.get_field_value(data)
        return self.text_wrap(str(field_value), width)


class WrapperWithCustomFormatter(WrapperLambdaFormatter):
    """A wrapper formatter that allows the programmer to have a custom
       formatter (in the form of a function) that is first applied
       and then a wrapper function is applied to the result

       See wrapperFormatterFactory for a better explanation! :-)
    """

    # noinspection PyUnusedLocal
    def __init__(self, ctx, field, custom_formatter, wrapper_formatter):
        super(WrapperWithCustomFormatter, self).__init__(ctx, None,
                                                         lambda data: wrapper_formatter.format(custom_formatter(data)))
        self.wrapper_formatter = wrapper_formatter
        self.custom_formatter = custom_formatter

    def get_unwrapped_field_value(self, data):
        return self.custom_formatter(data)

    def __setattr__(self, name, value):
        #
        # Some attributes set onto this class need
        # to be pushed down to the 'inner' wrapper_formatter
        #
        super(WrapperWithCustomFormatter, self).__setattr__(name, value)
        if hasattr(self, "wrapper_formatter"):
            if name == "no_wrap":
                self.wrapper_formatter.no_wrap = value
            if name == "add_blank_line":
                self.wrapper_formatter.add_blank_line = value
            if name == "header_width":
                self.wrapper_formatter.header_width = value

    def set_min_width(self, min_width):
        super(WrapperWithCustomFormatter, self).set_min_width(min_width)
        self.wrapper_formatter.set_min_width(min_width)

    def set_actual_column_len(self, actual):
        super(WrapperWithCustomFormatter, self).set_actual_column_len(actual)
        self.wrapper_formatter.set_actual_column_len(actual)

    def get_basic_desired_width(self):
        return self.wrapper_formatter.get_basic_desired_width()


def wrapper_formatter_factory(ctx, field, formatter):
    """
    This function is a factory for building WrapperFormatter objects.

    The function needs to be called for each celldata column (field)
    that will be displayed in the prettyTable.

    The function looks at the formatter parameter and based on its type,
    determines what WrapperFormatter to construct per field (column).

    ex:

    formatter = 15 - type = int :  Builds a WrapperFixedWidthFormatter that
                                   will wrap at 15 chars

    formatter = .25 - type = int : Builds a WrapperPercentWidthFormatter that
                                   will wrap at 25% terminal width

    formatter = type = callable :  Builds a WrapperLambdaFormatter that
                                   will call some arbitrary function

    formatter = type = dict :      Builds a WrapperWithCustomFormatter that
                                   will call some arbitrary function to format
                                   and then apply a wrapping formatter to the result

                                    ex: this dict {"formatter" : captializeFunction,,
                                                   "wrapperFormatter":  .12}
                                    will apply the captializeFunction to the column
                                    celldata and then wordwrap at 12 % of terminal width

    :param ctx:  the WrapperContext that the built WrapperFormatter will use
    :param field:   name of field (column_ that the WrapperFormatter will execute on
    :param formatter: specifies type and input for WrapperFormatter that will be built
    :return: WrapperFormatter

    """
    if isinstance(formatter, WrapperFormatter):
        return formatter
    if callable(formatter):
        return WrapperLambdaFormatter(ctx, field, formatter)
    if isinstance(formatter, int):
        return WrapperFixedWidthFormatter(ctx, field, formatter)
    if isinstance(formatter, float):
        return WrapperPercentWidthFormatter(ctx, field, formatter)
    if isinstance(formatter, dict):
        if "wrapperFormatter" in formatter:
            embedded_wrapper_formatter = wrapper_formatter_factory(ctx, None,
                                                                   formatter["wrapperFormatter"])
        elif "hard_width" in formatter:
            embedded_wrapper_formatter = WrapperFixedWidthFormatter(ctx, field, formatter["hard_width"])
            embedded_wrapper_formatter.min_width = formatter["hard_width"]
        else:
            embedded_wrapper_formatter = WrapperFormatter(ctx, None)  # effectively a NOOP width formatter
        if "formatter" not in formatter:
            return embedded_wrapper_formatter
        custom_formatter = formatter["formatter"]
        wrapper = WrapperWithCustomFormatter(ctx, field, custom_formatter, embedded_wrapper_formatter)
        return wrapper

    raise Exception("Formatter Error! Unrecognized formatter {} for field {}".format(formatter, field))


def build_column_stats_for_best_guess_formatting(objs, fields, field_labels, custom_formatters={}):
    class ColumnStats:
        def __init__(self, field, field_label, custom_formatter=None):
            self.field = field
            self.field_label = field_label
            self.average_width = 0
            self.min_width = _get_width(field_label) if field_label else 0
            self.max_width = _get_width(field_label) if field_label else 0
            self.total_width = 0
            self.count = 0
            self.average_percent = 0
            self.max_percent = 0
            self.isUUID = is_uuid_field(field)
            if custom_formatter:
                self.get_field_value = custom_formatter
            else:
                self.get_field_value = field_value_function_factory(self, field)

        def add_value(self, value):
            if self.isUUID:
                return
            self.count += 1
            value_width = _get_width(value)
            self.total_width = self.total_width + value_width
            if value_width < self.min_width:
                self.min_width = value_width
            if value_width > self.max_width:
                self.max_width = value_width
            if self.count > 0:
                self.average_width = float(self.total_width) / float(self.count)

        def set_max_percent(self, max_total_width):
            if max_total_width > 0:
                self.max_percent = float(self.max_width) / float(max_total_width)

        def set_avg_percent(self, avg_total_width):
            if avg_total_width > 0:
                self.average_percent = float(self.average_width) / float(avg_total_width)

        def __str__(self):
            return str([self.field,
                        self.average_width,
                        self.min_width,
                        self.max_width,
                        self.total_width,
                        self.count,
                        self.average_percent,
                        self.max_percent,
                        self.isUUID])

        def __repr__(self):
            return str([self.field,
                        self.average_width,
                        self.min_width,
                        self.max_width,
                        self.total_width,
                        self.count,
                        self.average_percent,
                        self.max_percent,
                        self.isUUID])

    if objs is None or len(objs) == 0:
        return {"stats": {},
                "total_max_width": 0,
                "total_avg_width": 0}

    stats = {}
    for i in range(0, len(fields)):
        stats[fields[i]] = ColumnStats(fields[i], field_labels[i], custom_formatters.get(fields[i]))

    for obj in objs:
        for field in fields:
            column_stat = stats[field]
            column_stat.add_value(column_stat.get_field_value(obj))

    total_max_width = sum([s.max_width for s in stats.values()])
    total_avg_width = sum([s.average_width for s in stats.values()])
    return {"stats": stats,
            "total_max_width": total_max_width,
            "total_avg_width": total_avg_width}


def build_best_guess_formatters_using_average_widths(objs, fields, field_labels, custom_formatters={}, no_wrap_fields=[]):
    column_info = build_column_stats_for_best_guess_formatting(objs, fields, field_labels, custom_formatters)
    format_spec = {}
    total_avg_width = float(column_info["total_avg_width"])
    if total_avg_width <= 0:
        return format_spec
    for f in [ff for ff in fields if ff not in no_wrap_fields]:
        format_spec[f] = float(column_info["stats"][f].average_width) / total_avg_width
        custom_formatter = custom_formatters.get(f, None)
        if custom_formatter:
            format_spec[f] = {"formatter": custom_formatter, "wrapperFormatter": format_spec[f]}

    # Handle no wrap fields by building formatters that will not wrap
    for f in [ff for ff in fields if ff in no_wrap_fields]:
        format_spec[f] = {"hard_width": column_info["stats"][f].max_width}
        custom_formatter = custom_formatters.get(f, None)
        if custom_formatter:
            format_spec[f] = {"formatter": custom_formatter, "wrapperFormatter": format_spec[f]}
    return format_spec


def build_best_guess_formatters_using_max_widths(objs, fields, field_labels, custom_formatters={}, no_wrap_fields=[]):
    column_info = build_column_stats_for_best_guess_formatting(objs, fields, field_labels, custom_formatters)
    format_spec = {}
    for f in [ff for ff in fields if ff not in no_wrap_fields]:
        format_spec[f] = float(column_info["stats"][f].max_width) / float(column_info["total_max_width"])
        custom_formatter = custom_formatters.get(f, None)
        if custom_formatter:
            format_spec[f] = {"formatter": custom_formatter, "wrapperFormatter": format_spec[f]}

    # Handle no wrap fields by building formatters that will not wrap
    for f in [ff for ff in fields if ff in no_wrap_fields]:
        format_spec[f] = {"hard_width": column_info["stats"][f].max_width}
        custom_formatter = custom_formatters.get(f, None)
        if custom_formatter:
            format_spec[f] = {"formatter": custom_formatter, "wrapperFormatter": format_spec[f]}

    return format_spec


def needs_wrapping_formatters(formatters, no_wrap=None):
    no_wrap = is_nowrap_set(no_wrap)
    if no_wrap:
        return False

    # handle easy case:
    if not formatters:
        return True

    # If we have at least one wrapping formatter,
    # then we assume we don't need to wrap
    for f in formatters.values():
        if WrapperFormatter.is_wrapper_formatter(f):
            return False

    # looks like we need wrapping
    return True


def as_wrapping_formatters(objs, fields, field_labels, formatters, no_wrap=None, no_wrap_fields=[]):
    """This function is the entry point for building the "best guess"
       word wrapping formatters.  A best guess formatter guesses what the best
       columns widths should be for the table celldata.  It does this by collecting
       various stats on the celldata (min, max average width of column celldata) and from
       this celldata decides the desired widths and the minimum widths.

       Given a list of formatters and the list of objects (objs),  this function
       first determines if we need to augment the passed formatters with word wrapping
       formatters.  If the no_wrap parameter or global no_wrap flag is set,
       then we do not build wrapping formatters.  If any of the formatters within formatters
       is a word wrapping formatter, then it is assumed no more wrapping is required.

    :param objs:
    :param fields:
    :param field_labels:
    :param formatters:
    :param no_wrap:
    :param no_wrap_fields:
    :return: When no wrapping is required, the formatters parameter is returned
              -- effectively a NOOP in this case

              When wrapping is required, best-guess word wrapping formatters are returned
              with original parameter formatters embedded in the word wrapping formatters
    """
    no_wrap = is_nowrap_set(no_wrap)

    if not needs_wrapping_formatters(formatters, no_wrap):
        return formatters

    format_spec = build_best_guess_formatters_using_average_widths(objs, fields, field_labels, formatters, no_wrap_fields)

    formatters = build_wrapping_formatters(objs, fields, field_labels, format_spec)

    return formatters


def build_wrapping_formatters(objs, fields, field_labels, format_spec, add_blank_line=True,
                              no_wrap=None, use_max=False):
    """
      A convenience function for building all wrapper formatters that will be used to
      format a CLI's output when its rendered in a prettyTable object.

      It iterates through the keys of format_spec and calls wrapperFormatterFactory to build
       wrapperFormatter objects for each column.

       Its best to show by example parameters:

        field_labels = ['UUID', 'Time Stamp', 'State', 'Event Log ID', 'Reason Text',
                        'Entity Instance ID', 'Severity']
        fields = ['uuid', 'timestamp', 'state', 'event_log_id', 'reason_text',
                  'entity_instance_id', 'severity']
        format_spec =  {
                            "uuid"                       : .10,  # float = so display as 10% of terminal width
                            "timestamp"                  : .08,
                            "state"                      : .08,
                            "event_log_id"               : .07,
                            "reason_text"                : .42,
                            "entity_instance_id"         : .13,
                            "severity"                   : {"formatter" : captializeFunction,
                                                            "wrapperFormatter":  .12}
                          }

    :param objs: the actual celldata that will get word wrapped
    :param fields:  fields (attributes of the celldata) that will be  displayed in the table
    :param field_labels: column (field headers)
    :param format_spec:  dict specify formatter for each column (field)
    :param add_blank_line: default True, when tru adds blank line to column if it wraps, aids readability
    :param no_wrap:  default False, when True turns wrapping off but does not suppress other custom formatters
    :param use_max
    :return: wrapping formatters as functions
    """

    no_wrap = set_no_wrap(no_wrap)

    if objs is None or len(objs) == 0:
        return {}

    biggest_word_pattern = re.compile("[\.:,;\!\?\\ =-\_]")

    def get_biggest_word(s):
        return max(biggest_word_pattern.split(s), key=len)

    wrapping_formatters_as_functions = {}

    if len(fields) != len(field_labels):
        raise Exception("Error in buildWrappingFormatters: "
                        "len(fields) = {}, len(field_labels) = {},"
                        " they must be the same length!".format(len(fields),
                                                                len(field_labels)))
    field_to_label = {}

    for i in range(0, len(fields)):
        field_to_label[fields[i]] = field_labels[i]

    ctx = WrapperContext()
    ctx.set_num_columns(len(fields))

    if not format_spec:
        if use_max:
            format_spec = build_best_guess_formatters_using_max_widths(objs, fields, field_labels)
        else:
            format_spec = build_best_guess_formatters_using_average_widths(objs, fields, field_labels)

    for k in format_spec.keys():
        if k not in fields:
            raise Exception("Error in buildWrappingFormatters: format_spec "
                            "specifies a field {} that is not specified "
                            "in fields : {}".format(k, fields))

        format_spec_for_k = copy.deepcopy(format_spec[k])
        if callable(format_spec_for_k):
            format_spec_for_k = {"formatter": format_spec_for_k}
        wrapper_formatter = wrapper_formatter_factory(ctx, k, format_spec_for_k)
        if wrapper_formatter.min_width <= 0:
            # need to specify min-width so that
            # column is not unnecessarily squashed
            if is_uuid_field(k):  # special case
                wrapper_formatter.set_min_width(UUID_MIN_LENGTH)
            else:
                # column width cannot be smaller than the widest word
                column_data = [str(wrapper_formatter.get_unwrapped_field_value(data)) for data in objs]
                widest_word_in_column = max([get_biggest_word(d) + " "
                                             for d in column_data + [field_to_label[k]]], key=len)
                wrapper_formatter.set_min_width(len(widest_word_in_column))
                wrapper_formatter.header_width = _get_width(field_to_label[k])

        wrapper_formatter.add_blank_line = add_blank_line
        wrapper_formatter.no_wrap = no_wrap
        wrapping_formatters_as_functions[k] = wrapper_formatter.as_function()
        ctx.add_column_formatter(k, wrapper_formatter)

    return wrapping_formatters_as_functions


def set_no_wrap_on_formatters(no_wrap, formatters):
    """
       Purpose of this function is to temporarily force
       the no_wrap setting for the formatters parameter.
       returns orig_no_wrap_settings defined for each formatter
       Use unset_no_wrap_on_formatters(orig_no_wrap_settings) to undo what
       this function does
    """
    # handle easy case:
    if not formatters:
        return {}

    formatter_no_wrap_settings = {}

    global_orig_no_wrap = is_nowrap_set()
    set_no_wrap(no_wrap)

    for k, f in formatters.items():
        if WrapperFormatter.is_wrapper_formatter(f):
            formatter_no_wrap_settings[k] = (f.wrapper_formatter.no_wrap, f.wrapper_formatter)
            f.wrapper_formatter.no_wrap = no_wrap

    return {"global_orig_no_wrap": global_orig_no_wrap,
            "formatter_no_wrap_settings": formatter_no_wrap_settings}


def unset_no_wrap_on_formatters(orig_no_wrap_settings):
    """
        It only makes sense to call this function with the return value
        from the last call to set_no_wrap_on_formatters(no_wrap, formatters).
        It effectively undoes what set_no_wrap_on_formatters() does
    """
    if not orig_no_wrap_settings:
        return {}

    global_orig_no_wrap = orig_no_wrap_settings["global_orig_no_wrap"]
    formatter_no_wrap_settings = orig_no_wrap_settings["formatter_no_wrap_settings"]

    formatters = {}

    for k, v in formatter_no_wrap_settings.items():
        formatters[k] = v[1]
        formatters[k].no_wrap = v[0]

    set_no_wrap(global_orig_no_wrap)

    return formatters


def _simpleTestHarness(no_wrap):

    from cgtsclient.common import utils

    def testFormatter(event):
        return "*{}".format(event["state"])

    def buildFormatter(field, width):
        def f(dict):
            if field == 'number':
                return dict[field]
            return "{}".format(dict[field]).replace("_", " ")
        return {"formatter": f, "wrapperFormatter": width}

    set_no_wrap(no_wrap)

    field_labels = ['Time Stamp', 'State', 'Event Log ID', 'Reason Text',
                    'Entity Instance ID', 'Severity', 'Number']
    fields = ['timestamp', 'state', 'event_log_id', 'reason_text',
              'entity_instance_id', 'severity', 'number']

    formatterSpecX = {"timestamp": 10,
                      "state": 8,
                      "event_log_id": 70,
                      "reason_text": 30,
                      "entity_instance_id": 30,
                      "severity": 12,
                      "number": 4}

    formatterSpec = {}
    for f in fields:
        formatterSpec[f] = buildFormatter(f, formatterSpecX[f])

    logs = []
    for i in range(0, 30):
        log = {}
        for f in fields:
            if f == 'number':
                log[f] = i
            else:
                log[f] = "{}{}".format(f, i)
        logs.append(utils.objectify(log))

    formatterSpec = formatterSpecX

    formatters = build_wrapping_formatters(logs, fields, field_labels, formatterSpec)

    utils.print_list(logs, fields, field_labels, formatters=formatters, sortby=6,
                     reversesort=True, no_wrap_fields=['entity_instance_id'])

    print("nowrap = {}".format(is_nowrap_set()))


if __name__ == "__main__":
    _simpleTestHarness(True)
    _simpleTestHarness(False)
