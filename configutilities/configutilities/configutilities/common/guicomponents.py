#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import wx

from configutilities.common.exceptions import ValidateFail
from configutilities.common import wrs_ico

TEXT_BOX_SIZE = (150, -1)
TEXT_WIDTH = 450
DEBUG = False
VGAP = 5
HGAP = 10


def debug(msg):
    if DEBUG:
        print(msg)


# Tracks what type of controls will implement a config question
class TYPES(object):
    string = 1
    int = 2
    radio = 3
    choice = 4
    checkbox = 5
    help = 6
    separator = 7


class Field(object):
    def __init__(self, text="", type=TYPES.string, transient=False,
                 initial="", choices=[], shows=[], reverse=False,
                 enabled=True):
        """Represent a configuration question

        :param text: Question prompt text

        :param type: The type of wxWidgets control(s) used to implement this
                field

        :param transient: Whether this field should be written automatically
                to the INI file

        :param enabled: Whether this field should be enabled or
                        disabled (greyed-out)

        :param initial: Initial value used to populate the control

        :param choices: A string list of choices to populate selection-based
                        fields

        :param shows: A list of field key strings that this field should show
                when checked.  Only checkboxes implement this functionality atm

        :param reverse: Switches the 'shows' logic -> checked
                will hide fields instead of showing them

        :return: the Field object
        """

        self.text = text
        self.type = type
        self.transient = transient
        self.initial = initial
        self.choices = choices
        self.shows = shows
        self.reverse = reverse
        self.enabled = enabled

        # Controls used to implement this field
        self.prompt = None
        self.input = None

        if type is TYPES.help:
            self.transient = True

        # Sanity to make sure fields are being utilized correctly
        if self.shows and self.type is TYPES.help:
            raise NotImplementedError()

        if not self.shows and self.reverse:
            raise NotImplementedError()

    def get_value(self):
        # Return value of the control (a string or int)
        if not self.input:
            value = None
        elif not self.input.IsShown() or not self.input.IsEnabled():
            value = None
        elif self.type is TYPES.string:
            value = self.input.GetLineText(0)
        elif self.type is TYPES.int:
            try:
                value = self.input.GetLineText(0)
                int(value)
            except ValueError:
                raise ValidateFail(
                    "Invalid entry for %s. Must enter a numeric value" %
                    self.text)
        elif self.type is TYPES.radio:
            value = self.input.GetString(self.input.GetSelection())
        elif self.type is TYPES.choice:
            value = self.input.GetString(self.input.GetSelection())
        elif self.type is TYPES.checkbox:
            value = "N"
            if self.input.GetValue():
                value = "Y"
        else:
            raise NotImplementedError()

        return value

    def set_value(self, value):
        # Set value of the control (string or int)
        if not self.input:
            # Can't 'set' help text etc.
            raise NotImplementedError()
        elif self.type is TYPES.string or self.type is TYPES.int:
            self.input.SetValue(value)
        elif self.type is TYPES.radio or self.type is TYPES.choice:
            index = self.input.FindString(value)
            if index == wx.NOT_FOUND:
                raise ValidateFail("Invalid value %s for field %s" %
                                   (value, self.text))
            self.input.SetSelection(index)
        elif self.type is TYPES.checkbox:
            self.input.SetValue(value == "Y")
        else:
            raise NotImplementedError()

    def destroy(self):
        if self.prompt:
            self.prompt.Destroy()
        if self.input:
            self.input.Destroy()

    def show(self, visible):
        debug("Setting visibility to %s for field %s prompt=%s" %
              (visible, self.text, self.prompt))
        if visible:
            if self.prompt:
                self.prompt.Show()
            if self.input:
                self.input.Show()
        else:
            if self.prompt:
                self.prompt.Hide()
            if self.input:
                self.input.Hide()


def prepare_fields(parent, fields, sizer, change_hdlr):
        for row, (name, field) in enumerate(fields.items()):
            initial = field.initial
            # if config.has_option(parent.section, name):
            #    initial = config.get(parent.section, name)

            add_attributes = wx.ALIGN_CENTER_VERTICAL
            width = 1
            field.prompt = wx.StaticText(parent, label=field.text, name=name)

            # Generate different control based on field type
            if field.type is TYPES.string or field.type is TYPES.int:
                field.input = wx.TextCtrl(parent, value=initial, name=name,
                                          size=TEXT_BOX_SIZE)

            elif field.type is TYPES.radio:
                field.input = wx.RadioBox(
                    parent, choices=field.choices, majorDimension=1,
                    style=wx.RA_SPECIFY_COLS, name=name, id=wx.ID_ANY)

            elif field.type is TYPES.choice:
                field.input = wx.Choice(
                    parent, choices=field.choices, name=name)
                if initial:
                    field.input.SetSelection(field.input.FindString(initial))
            elif field.type is TYPES.checkbox:
                width = 2
                field.input = wx.CheckBox(parent, name=name, label=field.text,
                                          )  # style=wx.ALIGN_RIGHT)
                field.input.SetValue(initial == 'Y')
                if field.prompt:
                    field.prompt.Hide()
                field.prompt = None

            elif field.type is TYPES.help:
                width = 2
                field.prompt.Wrap(TEXT_WIDTH)
                field.input = None

            elif field.type is TYPES.separator:
                width = 2
                field.prompt = wx.StaticLine(parent, -1)
                add_attributes = wx.EXPAND | wx.ALL
                field.input = None

            else:
                raise NotImplementedError()

            col = 0
            if field.prompt:
                sizer.Add(field.prompt, (row, col), span=(1, width),
                          flag=add_attributes)
                col += 1
            if field.input:
                field.input.Enable(field.enabled)
                sizer.Add(field.input, (row, col),
                          flag=add_attributes)

        # Go through again and set show/hide relationships
        for name, field in fields.items():
            if field.shows:
                # Add display handlers
                field.input.Bind(wx.EVT_CHECKBOX, change_hdlr)
                # todo tsmith add other evts

                # Start by hiding target prompt/input controls
                for target_name in field.shows:
                    target = fields[target_name]
                    if target.prompt:
                        target.prompt.Hide()
                    if target.input:
                        target.input.Hide()


def on_change(parent, fields, event):
    obj = event.GetEventObject()

    # debug("Checked: " + str(event.Checked()) +
    #    ", Reverse: " + str(parent.fields[obj.GetName()].reverse) +
    #    ", Will show: " + str(event.Checked() is not
    # parent.fields[obj.GetName()].reverse))

    # Hide/Show the targets of the control
    # Note: the "is not" implements switching the show logic around
    handle_sub_show(
        fields,
        fields[obj.GetName()].shows,
        event.Checked() is not fields[obj.GetName()].reverse)

    parent.Layout()
    event.Skip()


def handle_sub_show(fields, targets, show):
    """ Recursive function to handle showing/hiding of a list of fields
     :param targets: [String]
     :param show: bool
    """

    sub_handled = []
    for tgt in targets:
        if tgt in sub_handled:
            # Handled by newly shown control
            continue

        tgt_field = fields[tgt]
        # Show or hide this field as necessary
        tgt_field.show(show)

        # If it shows others (checkbox) and is now shown,
        # apply it's value decide on showing it's children, not the
        # original show
        if tgt_field.shows and show:
            sub_handled.extend(tgt_field.shows)
            handle_sub_show(
                fields,
                tgt_field.shows,
                (tgt_field.get_value() is 'Y') is not fields[tgt].reverse)


def set_icons(parent):
    # Icon setting
    # todo Make higher resolution icons, verify on different linux desktops
    icons = wx.IconBundle()
    for sz in [16, 32, 48]:
        # try:
        # icon = wx.Icon(wrs_ico.windriver_favicon.getIcon(),
        #               width=sz, height=sz)
        icon = wrs_ico.favicon.getIcon()
        icons.AddIcon(icon)
        # except:
        #    pass
    parent.SetIcons(icons)

    # ico = wrs_ico.windriver_favicon.getIcon()
    # self.SetIcon(ico)

    # self.tbico = wx.TaskBarIcon()
    # self.tbico.SetIcon(ico, '')
