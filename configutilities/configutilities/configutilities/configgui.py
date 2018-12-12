"""
Copyright (c) 2015-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import wx

from configutilities.common.guicomponents import set_icons
from configutilities.common.validator import TiS_VERSION
from configutilities import configfiletool
from configutilities import hostfiletool

TEXT_WIDTH = 560
BTN_SIZE = (200, -1)


class WelcomeScreen(wx.Frame):
    def __init__(self, *args, **kwargs):
        super(WelcomeScreen, self).__init__(*args, **kwargs)
        page = Content(self)

        set_icons(self)

        size = page.main_sizer.Fit(self)
        self.SetMinSize(size)
        self.Layout()


class Content(wx.Panel):
    def __init__(self, *args, **kwargs):
        super(Content, self).__init__(*args, **kwargs)

        self.title = wx.StaticText(
            self, -1,
            'Titanium Cloud Configuration Utility')
        self.title.SetFont(wx.Font(18, wx.SWISS, wx.NORMAL, wx.BOLD))

        # Set up controls for the main page
        self.description = wx.StaticText(
            self, -1,
            ' Welcome, The following tools are available for use:')

        self.config_desc = wx.StaticText(
            self, -1,
            "The Titanium Cloud configuration file wizard allows users to "
            "create the configuration INI file which is used during the "
            "installation process")
        self.config_desc.Wrap(TEXT_WIDTH / 2)
        self.hosts_desc = wx.StaticText(
            self, -1,
            "The Titanium Cloud host file tool allows users to create an XML "
            "file specifying hosts to be provisioned as part of the Titanium "
            "Cloud cloud deployment.")
        self.hosts_desc.Wrap(TEXT_WIDTH / 2)

        self.config_wiz_btn = wx.Button(
            self, -1, "Launch Config File Wizard", size=BTN_SIZE)
        self.Bind(wx.EVT_BUTTON, self.launch_config_wiz, self.config_wiz_btn)

        self.host_file_tool_btn = wx.Button(
            self, -1, "Launch Host File Tool", size=BTN_SIZE)
        self.Bind(wx.EVT_BUTTON, self.launch_host_wiz, self.host_file_tool_btn)

        self.box1 = wx.StaticBox(self)
        self.box2 = wx.StaticBox(self)

        # Do layout of controls
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)
        self.tool1Sizer = wx.StaticBoxSizer(self.box1, wx.HORIZONTAL)
        self.tool2Sizer = wx.StaticBoxSizer(self.box2, wx.HORIZONTAL)

        self.main_sizer.AddSpacer(10)
        self.main_sizer.Add(self.title, flag=wx.ALIGN_CENTER)
        self.main_sizer.AddSpacer(10)
        self.main_sizer.Add(self.description)
        self.main_sizer.AddSpacer(5)
        self.main_sizer.Add(self.tool1Sizer, proportion=1, flag=wx.EXPAND)
        self.main_sizer.Add(self.tool2Sizer, proportion=1, flag=wx.EXPAND)
        self.main_sizer.AddSpacer(5)

        self.tool1Sizer.Add(self.config_desc, flag=wx.ALIGN_CENTER)
        self.tool1Sizer.AddSpacer(10)
        self.tool1Sizer.Add(self.config_wiz_btn, flag=wx.ALIGN_CENTER)
        self.tool2Sizer.Add(self.hosts_desc, flag=wx.ALIGN_CENTER)
        self.tool2Sizer.AddSpacer(10)
        self.tool2Sizer.Add(self.host_file_tool_btn, flag=wx.ALIGN_CENTER)

        self.SetSizer(self.main_sizer)

        self.Layout()

    def launch_config_wiz(self, event):
        conf_wizard = configfiletool.ConfigWizard()
        conf_wizard.run()
        conf_wizard.Destroy()

    def launch_host_wiz(self, event):
        hostfiletool.HostGUI()


def main():
    app = wx.App(0)  # Start the application

    gui = WelcomeScreen(None, title="Titanium Cloud Configuration Utility v"
                                    + TiS_VERSION)
    gui.Show()
    app.MainLoop()
    app.Destroy()


if __name__ == '__main__':
    main()
