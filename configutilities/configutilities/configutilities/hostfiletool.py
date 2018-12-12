"""
Copyright (c) 2015-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from collections import OrderedDict
import netaddr
import xml.etree.ElementTree as ET

import wx

from configutilities.common import utils
from configutilities.common import exceptions
from configutilities.common.guicomponents import Field
from configutilities.common.guicomponents import TYPES
from configutilities.common.guicomponents import prepare_fields
from configutilities.common.guicomponents import on_change
from configutilities.common.guicomponents import set_icons
from configutilities.common.guicomponents import handle_sub_show
from configutilities.common.configobjects import HOST_XML_ATTRIBUTES
from configutilities.common.validator import TiS_VERSION

PAGE_SIZE = (200, 200)
WINDOW_SIZE = (570, 700)
CB_TRUE = True
CB_FALSE = False
PADDING = 10

IMPORT_ID = 100
EXPORT_ID = 101

INTERNAL_ID = 105
EXTERNAL_ID = 106

filedir = ""
filename = ""

# Globals
BULK_ADDING = False


class HostPage(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent=parent)

        self.parent = parent
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self.sizer)
        self.fieldgroup = []
        self.fieldgroup.append(OrderedDict())
        self.fieldgroup.append(OrderedDict())
        self.fieldgroup.append(OrderedDict())

        self.fields_sizer1 = wx.GridBagSizer(vgap=10, hgap=10)
        self.fields_sizer2 = wx.GridBagSizer(vgap=10, hgap=10)
        self.fields_sizer3 = wx.GridBagSizer(vgap=10, hgap=10)

        # Basic Fields
        self.fieldgroup[0]['personality'] = Field(
            text="Personality",
            type=TYPES.choice,
            choices=['compute', 'controller', 'storage'],
            initial='compute'
        )
        self.fieldgroup[0]['hostname'] = Field(
            text="Hostname",
            type=TYPES.string,
            initial=parent.get_next_hostname()
        )
        self.fieldgroup[0]['mgmt_mac'] = Field(
            text="Management MAC Address",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[0]['mgmt_ip'] = Field(
            text="Management IP Address",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[0]['location'] = Field(
            text="Location",
            type=TYPES.string,
            initial=""
        )

        # Board Management
        self.fieldgroup[1]['uses_bm'] = Field(
            text="This host uses Board Management",
            type=TYPES.checkbox,
            initial="",
            shows=['bm_ip', 'bm_username',
                   'bm_password', 'power_on'],
            transient=True
        )
        self.fieldgroup[1]['bm_ip'] = Field(
            text="Board Management IP Address",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[1]['bm_username'] = Field(
            text="Board Management username",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[1]['bm_password'] = Field(
            text="Board Management password",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[1]['power_on'] = Field(
            text="Power on host",
            type=TYPES.checkbox,
            initial="N",
            transient=True
        )

        # Installation Parameters
        self.fieldgroup[2]['boot_device'] = Field(
            text="Boot Device",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[2]['rootfs_device'] = Field(
            text="Rootfs Device",
            type=TYPES.string,
            initial=""
        )
        self.fieldgroup[2]['install_output'] = Field(
            text="Installation Output",
            type=TYPES.choice,
            choices=['text', 'graphical'],
            initial="text"
        )
        self.fieldgroup[2]['console'] = Field(
            text="Console",
            type=TYPES.string,
            initial=""
        )

        prepare_fields(self, self.fieldgroup[0], self.fields_sizer1,
                       self.on_change)
        prepare_fields(self, self.fieldgroup[1], self.fields_sizer2,
                       self.on_change)
        prepare_fields(self, self.fieldgroup[2], self.fields_sizer3,
                       self.on_change)

        # Bind button handlers
        self.Bind(wx.EVT_CHOICE, self.on_personality,
                  self.fieldgroup[0]['personality'].input)

        self.Bind(wx.EVT_TEXT, self.on_hostname,
                  self.fieldgroup[0]['hostname'].input)

        # Control Buttons
        self.button_sizer = wx.BoxSizer(orient=wx.HORIZONTAL)

        self.add = wx.Button(self, -1, "Add a New Host")
        self.Bind(wx.EVT_BUTTON, self.on_add, self.add)

        self.remove = wx.Button(self, -1, "Remove this Host")
        self.Bind(wx.EVT_BUTTON, self.on_remove, self.remove)

        self.button_sizer.Add(self.add)
        self.button_sizer.Add(self.remove)

        # Add fields and spacers
        self.sizer.Add(self.fields_sizer1)
        self.sizer.AddWindow(wx.StaticLine(self, -1), 0, wx.EXPAND | wx.ALL,
                             PADDING)
        self.sizer.Add(self.fields_sizer2)
        self.sizer.AddWindow(wx.StaticLine(self, -1), 0, wx.EXPAND | wx.ALL,
                             PADDING)
        self.sizer.Add(self.fields_sizer3)
        self.sizer.AddStretchSpacer()
        self.sizer.AddWindow(wx.StaticLine(self, -1), 0, wx.EXPAND | wx.ALL,
                             PADDING)
        self.sizer.Add(self.button_sizer, border=10, flag=wx.CENTER)

    def on_hostname(self, event, string=None):
        """Update the List entry text to match the new hostname
        """
        string = string or event.GetString()
        index = self.parent.GetSelection()
        self.parent.SetPageText(index, string)
        self.parent.parent.Layout()

    def on_personality(self, event, string=None):
        """Remove hostname field if it's a storage or controller
        """
        string = string or event.GetString()
        index = self.parent.GetSelection()
        if string == 'compute':
            self.fieldgroup[0]['hostname'].show(True)
            self.parent.SetPageText(index,
                                    self.fieldgroup[0]['hostname'].get_value())
            return
        elif string == 'controller':
            self.fieldgroup[0]['hostname'].show(False)
        elif string == 'storage':
            self.fieldgroup[0]['hostname'].show(False)
        self.parent.SetPageText(index, string)
        self.parent.Layout()

    def on_add(self, event):
        try:
            self.validate()
        except Exception as ex:
            wx.LogError("Error on page: " + ex.message)
            return

        self.parent.new_page()

    def on_remove(self, event):
        if self.parent.GetPageCount() is 1:
            wx.LogError("Must leave at least one host")
            return
        index = self.parent.GetSelection()
        self.parent.DeletePage(index)

    def to_xml(self):
        """Create the XML for this host
        """
        self.validate()

        attrs = ""
        # Generic handling
        for fgroup in self.fieldgroup:
            for name, field in fgroup.items():
                if field.transient or not field.get_value():
                    continue
                attrs += "\t\t<" + name + ">" + \
                         field.get_value() + "</" + name + ">\n"

        # Special Fields
        if self.fieldgroup[1]['power_on'].get_value() is 'Y':
            attrs += "\t\t<power_on/>\n"

        if self.fieldgroup[1]['uses_bm'].get_value() is 'Y':
            attrs += "\t\t<bm_type>bmc</bm_type>\n"

        return "\t<host>\n" + attrs + "\t</host>\n"

    def validate(self):
        if self.fieldgroup[0]['personality'].get_value() == "compute" and not \
                utils.is_valid_hostname(
                    self.fieldgroup[0]['hostname'].get_value()):
            raise exceptions.ValidateFail(
                "Hostname %s is not valid" %
                self.fieldgroup[0]['hostname'].get_value())

        if not utils.is_valid_mac(self.fieldgroup[0]['mgmt_mac'].get_value()):
            raise exceptions.ValidateFail(
                "Management MAC address %s is not valid" %
                self.fieldgroup[0]['mgmt_mac'].get_value())

        ip = self.fieldgroup[0]['mgmt_ip'].get_value()
        if ip:
            try:
                netaddr.IPAddress(ip)
            except Exception:
                raise exceptions.ValidateFail(
                    "Management IP address %s is not valid" % ip)

        if self.fieldgroup[1]['uses_bm'].get_value() == 'Y':
            ip = self.fieldgroup[1]['bm_ip'].get_value()
            if ip:
                try:
                    netaddr.IPAddress(ip)
                except Exception:
                    raise exceptions.ValidateFail(
                        "Board Management IP address %s is not valid" % ip)

            else:
                raise exceptions.ValidateFail(
                    "Board Management IP is not specified.  "
                    "External Board Management Network requires Board "
                    "Management IP address.")

    def on_change(self, event):
        on_change(self, self.fieldgroup[1], event)

    def set_field(self, name, value):
        for fgroup in self.fieldgroup:
            for fname, field in fgroup.items():
                if fname == name:
                    field.set_value(value)


class HostBook(wx.Listbook):
    def __init__(self, parent):
        wx.Listbook.__init__(self, parent, style=wx.BK_DEFAULT)

        self.parent = parent
        self.Layout()
        # Add a starting host
        self.new_page()

        self.Bind(wx.EVT_LISTBOOK_PAGE_CHANGED, self.on_changed)
        self.Bind(wx.EVT_LISTBOOK_PAGE_CHANGING, self.on_changing)

    def on_changed(self, event):
        event.Skip()

    def on_changing(self, event):
        # Trigger page validation before leaving
        if BULK_ADDING:
            event.Skip()
            return
        index = self.GetSelection()
        try:
            if index != -1:
                self.GetPage(index).validate()
        except Exception as ex:
            wx.LogError("Error on page: " + ex.message)
            event.Veto()
            return
        event.Skip()

    def new_page(self, hostname=None):
        new_page = HostPage(self)
        self.AddPage(new_page, hostname or self.get_next_hostname())
        self.SetSelection(self.GetPageCount() - 1)
        return new_page

    def get_next_hostname(self, suggest=None):
        prefix = "compute-"
        new_suggest = suggest or 0

        for existing in range(self.GetPageCount()):
            if prefix + str(new_suggest) in self.GetPageText(existing):
                new_suggest = self.get_next_hostname(suggest=new_suggest + 1)

        if suggest:
            prefix = ""
        return prefix + str(new_suggest)

    def to_xml(self):
        """Create the complete XML and allow user to save
        """
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
              "<hosts version=\"" + TiS_VERSION + "\">\n"
        for index in range(self.GetPageCount()):
            try:
                xml += self.GetPage(index).to_xml()
            except Exception as ex:
                wx.LogError("Error on page number %s: %s" %
                            (index + 1, ex.message))
                return
        xml += "</hosts>"

        writer = wx.FileDialog(self,
                               message="Save Host XML File",
                               defaultDir=filedir or "",
                               defaultFile=filename or "TiS_hosts.xml",
                               wildcard="XML file (*.xml)|*.xml",
                               style=wx.FD_SAVE,
                               )

        if writer.ShowModal() == wx.ID_CANCEL:
            return

        # Write the XML file to disk
        try:
            with open(writer.GetPath(), "wb") as f:
                f.write(xml.encode('utf-8'))
        except IOError:
            wx.LogError("Error writing hosts xml file '%s'." %
                        writer.GetPath())


class HostGUI(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, wx.ID_ANY,
                          "Titanium Cloud Host File Creator v" + TiS_VERSION,
                          size=WINDOW_SIZE)
        self.panel = wx.Panel(self)

        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.book = HostBook(self.panel)
        self.sizer.Add(self.book, 1, wx.ALL | wx.EXPAND, 5)
        self.panel.SetSizer(self.sizer)
        set_icons(self)

        menu_bar = wx.MenuBar()

        # File
        file_menu = wx.Menu()
        import_item = wx.MenuItem(file_menu, IMPORT_ID, '&Import')
        file_menu.AppendItem(import_item)
        export_item = wx.MenuItem(file_menu, EXPORT_ID, '&Export')
        file_menu.AppendItem(export_item)
        menu_bar.Append(file_menu, '&File')
        self.Bind(wx.EVT_MENU, self.on_import, id=IMPORT_ID)
        self.Bind(wx.EVT_MENU, self.on_export, id=EXPORT_ID)

        self.SetMenuBar(menu_bar)
        self.Layout()
        self.SetMinSize(WINDOW_SIZE)
        self.Show()

    def on_import(self, e):
        global BULK_ADDING
        try:
            BULK_ADDING = True
            msg = ""

            reader = wx.FileDialog(self,
                                   "Import Existing Titanium Cloud Host File",
                                   "", "", "XML file (*.xml)|*.xml",
                                   wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)

            if reader.ShowModal() == wx.ID_CANCEL:
                return

            # Read in the config file
            try:
                with open(reader.GetPath(), 'rb') as f:
                    contents = f.read()
                    root = ET.fromstring(contents)
            except Exception as ex:
                wx.LogError("Cannot parse host file, Error: %s." % ex)
                return

            # Check version of host file
            if root.get('version', "") != TiS_VERSION:
                msg += "Warning: This file was created using tools for a " \
                       "different version of Titanium Cloud than this tool " \
                       "was designed for (" + TiS_VERSION + ")"

            for idx, xmlhost in enumerate(root.findall('host')):
                hostname = None
                name_elem = xmlhost.find('hostname')
                if name_elem is not None:
                    hostname = name_elem.text
                new_host = self.book.new_page()
                self.book.GetSelection()
                try:
                    for attr in HOST_XML_ATTRIBUTES:
                        elem = xmlhost.find(attr)
                        if elem is not None and elem.text:
                            # Enable and display bm section if used
                            if attr == 'bm_type' and elem.text:
                                new_host.set_field("uses_bm", "Y")
                                handle_sub_show(
                                    new_host.fieldgroup[1],
                                    new_host.fieldgroup[1]['uses_bm'].shows,
                                    True)
                                new_host.Layout()

                            # Basic field setting
                            new_host.set_field(attr, elem.text)

                            # Additional functionality for special fields
                            if attr == 'personality':
                                # Update hostname visibility and page title
                                new_host.on_personality(None, elem.text)

                        # Special handling for presence of power_on element
                        if attr == 'power_on' and elem is not None:
                            new_host.set_field(attr, "Y")

                    new_host.validate()
                except Exception as ex:
                    if msg:
                        msg += "\n"
                    msg += "Warning: Added host %s has a validation error, " \
                           "reason: %s" % \
                           (hostname or ("with index " + str(idx)),
                            ex.message)
                    # No longer delete hosts with validation errors,
                    # The user can fix them up before exporting
                    # self.book.DeletePage(new_index)

            if msg:
                wx.LogWarning(msg)
        finally:
            BULK_ADDING = False
            self.Layout()

    def on_export(self, e):
        # Do a validation of current page first
        index = self.book.GetSelection()
        try:
            if index != -1:
                self.book.GetPage(index).validate()
        except Exception as ex:
            wx.LogError("Error on page: " + ex.message)
            return

        # Check for hostname conflicts
        hostnames = []
        for existing in range(self.book.GetPageCount()):
            hostname = self.book.GetPage(
                existing).fieldgroup[0]['hostname'].get_value()
            if hostname in hostnames:
                wx.LogError("Cannot export, duplicate hostname '%s'" %
                            hostname)
                return
            # Ignore multiple None hostnames
            elif hostname:
                hostnames.append(hostname)

        self.book.to_xml()


def main():
    app = wx.App(0)  # Start the application
    HostGUI()
    app.MainLoop()


if __name__ == '__main__':
    main()
