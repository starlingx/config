"""
Copyright (c) 2015-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from collections import OrderedDict
from six.moves import configparser
import wx
import wx.wizard as wiz
import wx.lib.dialogs
import wx.lib.scrolledpanel

from common.configobjects import REGION_CONFIG, DEFAULT_CONFIG
from common.exceptions import ValidateFail
from common.guicomponents import Field, TYPES, prepare_fields, on_change, \
    debug, set_icons, TEXT_WIDTH, VGAP, HGAP
from common.validator import ConfigValidator, TiS_VERSION

PADDING = 5
CONFIG_TYPE = DEFAULT_CONFIG

LINK_SPEED_1G = '1000'
LINK_SPEED_10G = '10000'
LINK_SPEED_25G = '25000'

# Config parser to hold current configuration
filename = None
filedir = None
config = configparser.RawConfigParser()
config.optionxform = str


def print_config(conf=config):
    debug('======CONFIG CONTENTS======')
    debug(get_config(config))
    debug('======END CONFIG======')


def get_config(conf=config):
    result = ""
    for section in conf.sections():
        result += "\n[" + section + "]" + "\n"
        for option in config.options(section):
            result += option + "=" + config.get(section, option) + "\n"
    return result


def get_opt(section, option):
    if config.has_section(section):
        if config.has_option(section, option):
            return config.get(section, option)
    return None


class ConfigWizard(wx.wizard.Wizard):
    """Titanium Cloud configuration wizard, contains pages and more specifically
    ConfigPages, which have a structure for populating/processing
    configuration fields (questions)
    """
    def __init__(self):
        wx.wizard.Wizard.__init__(self, None, -1,
                                  "Titanium Cloud Configuration File "
                                  "Creator v" + TiS_VERSION)

        set_icons(self)

        self.pages = []
        # Catch wizard events
        self.Bind(wiz.EVT_WIZARD_PAGE_CHANGED, self.on_page_changed)
        self.Bind(wiz.EVT_WIZARD_PAGE_CHANGING, self.on_page_changing)
        self.Bind(wiz.EVT_WIZARD_CANCEL, self.on_cancel)
        self.Bind(wiz.EVT_WIZARD_FINISHED, self.on_finished)

        self.add_page(STARTPage(self))
        self.add_page(REGIONPage(self))
        self.add_page(SHAREDSERVICESPage(self))
        self.add_page(REG2SERVICESPage(self))
        self.add_page(REG2SERVICESPage2(self))
        self.add_page(SYSTEMPage(self))
        self.add_page(PXEBootPage(self))
        self.add_page(MGMTPage(self))
        self.add_page(INFRAPage(self))
        self.add_page(OAMPage(self))
        self.add_page(AUTHPage(self))
        self.add_page(ENDPage(self))

        size = self.GetBestSize()

        # Deprecated, from before scroll panel
        # for page in self.pages:
        #    if issubclass(type(page), ConfigPage):
        #        # Must create fields for the page and show them all
        #        # to get max possible size
        #        page.load()
        #        page.GetSizer().ShowItems(True)
        #        page_size = page.GetBestSize()
        #        if page_size.GetHeight() > size.GetHeight():
        #            size.SetHeight(page_size.GetHeight())
        #        if page_size.GetWidth() > size.GetWidth():
        #            size.SetWidth(page_size.GetWidth())
        #        page.DestroyChildren()

        size.SetWidth(560)
        size.SetHeight(530)
        self.SetPageSize(size)
        self.GetSizer().Layout()

    def add_page(self, page):
        """Add a new page"""
        if self.pages:
            previous_page = self.pages[-1]
            page.SetPrev(previous_page)
            previous_page.SetNext(page)
        self.pages.append(page)

    def run(self):
        """Start the wizard"""
        self.RunWizard(self.pages[0])

    def on_page_changed(self, evt):
        """Executed after the page has changed."""
        page = evt.GetPage()
        if evt.GetDirection():
            page.DestroyChildren()
            page.load()

    def on_page_changing(self, evt):
        """Executed before the page changes, can be blocked (vetoed)"""
        page = evt.GetPage()
        # Perform the page validation
        if evt.GetDirection():
            try:
                page.validate_page()
            except Exception as ex:
                dlg = wx.MessageDialog(  # ScrolledMessageDialog(
                    self,
                    ex.message,
                    "Error on page")
                dlg.ShowModal()
                # Do not allow progress if errors were raised
                evt.Veto()
                # raise ex

    def on_cancel(self, evt):
        """On cancel button press, not used for now"""
        pass

    def on_finished(self, evt):
        """On finish button press, not used for now"""
        pass

    def skip_page(self, page, skip):
        for p in self.pages:
            if p.__class__.__name__ == page.__name__:
                p.skip = skip


class WizardPage(wiz.PyWizardPage):
    """ An extended panel obj with a few methods to keep track of its siblings.
        This should be modified and added to the wizard.  Season to taste."""
    def __init__(self, parent):
        wx.wizard.PyWizardPage.__init__(self, parent)
        self.parent = parent
        self.title = ""
        self.next = self.prev = None
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self.sizer)
        self.skip = False

    def set_title(self, title_text):
        title = wx.StaticText(self, -1, title_text)
        title.SetFont(wx.Font(18, wx.SWISS, wx.NORMAL, wx.BOLD))
        self.sizer.AddWindow(title, 0, wx.ALIGN_LEFT | wx.ALL, PADDING)
        self.add_line()

    def add_content(self, content, proportion=0):
        """Add aditional widgets to the bottom of the page"""
        self.sizer.Add(content, proportion, wx.EXPAND | wx.ALL, PADDING)

    def add_line(self):
        self.sizer.AddWindow(wx.StaticLine(self, -1), 0, wx.EXPAND | wx.ALL,
                             PADDING)

    def SetNext(self, next):
        """Set the next page"""
        self.next = next

    def SetPrev(self, prev):
        """Set the previous page"""
        self.prev = prev

    def GetNext(self):
        """Return the next page"""
        if self.next and self.next.skip:
            return self.next.GetNext()
        return self.next

    def GetPrev(self):
        """Return the previous page"""
        if self.prev and self.prev.skip:
            return self.prev.GetPrev()
        return self.prev

    def load(self):
        # Run every time a page is visited (from prev or next page)
        pass

    def validate_page(self):
        # Validate the config related to this specific page before advancing
        pass


class ConfigPage(WizardPage):
    """ A Page of the wizard with questions/answers
    """
    def __init__(self, *args, **kwargs):
        super(ConfigPage, self).__init__(*args, **kwargs)
        # Section header to put in the INI file
        self.section = ""
        # Methods of the config_validator to be called for this section
        self.validator_methods = []
        self.title = ""
        self.help_text = ""
        self.fields = OrderedDict()

    def load(self):
        self.title = ""
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self.sizer)

        self.section = ""
        self.title = ""
        self.help_text = ""
        for field in self.fields.values():
            field.destroy()
        self.fields = OrderedDict()

    def do_setup(self):
        # Reset page, in case fields have changed
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.SetSizer(self.sizer)

        # Set up title and help text
        self.set_title(self.title)

        if self.help_text:
            help_text = wx.StaticText(self, -1, self.help_text)
            help_text.Wrap(TEXT_WIDTH)
            self.add_content(help_text)
            self.add_line()

        self.spanel = wx.lib.scrolledpanel.ScrolledPanel(self, -1)
        # to view spanel: , style=wx.SIMPLE_BORDER)
        self.add_content(self.spanel, 3)

        # Add fields to page
        # gridSizer = wx.FlexGridSizer(rows=6, cols=2, vgap=10,
        #                             hgap=10)
        self.gridSizer = wx.GridBagSizer(vgap=VGAP, hgap=HGAP)
        # gridSizer.SetFlexibleDirection(wx.VERTICAL)
        # gridSizer.SetFlexibleDirection(wx.BOTH)

        self.spanel.SetSizer(self.gridSizer)
        self.spanel.SetupScrolling()

        # self.add_content(gridSizer)

        prepare_fields(self.spanel, self.fields, self.gridSizer,
                       self.on_change)

        self.Layout()
        self.spanel.Layout()

    def on_change(self, event):
        on_change(self, self.fields, event)

    def validate_page(self):
        # Gets the config from the current page, then sends to the validator
        self.get_config()

        print_config(config)

        validator = ConfigValidator(config, None, CONFIG_TYPE, True)

        mode = get_opt('SYSTEM', 'SYSTEM_MODE')
        if mode:
            validator.set_system_mode(mode)

        dc_role = get_opt('SYSTEM', 'DISTRIBUTED_CLOUD_ROLE')
        if dc_role:
            validator.set_system_dc_role(dc_role)

        for method in self.validator_methods:
            getattr(validator, method)()

    def get_config(self):
        # Removes possibly out-dated config section so it can be over-written
        if config.has_section(self.section):
            config.remove_section(self.section)

        self.add_fields()

    def add_fields(self):
        # Adds the page's section to the config object if necessary
        if not config.has_section(self.section):
            config.add_section(self.section)

        # Add all of the non-transient fields (straight-forward mapping)
        for name, field in self.fields.items():
            if not field.transient and field.get_value():
                config.set(self.section, name, field.get_value())

    def bind_events(self):
        pass


class STARTPage(WizardPage):
    def load(self):
        super(STARTPage, self).load()

        self.set_title("Start")
        help_text = wx.StaticText(
            self, -1,
            "Welcome to the Titanium Cloud Configuration File "
            "Creator.\n\n"
            "This wizard will walk you through the steps of creating a "
            "configuration file which can be used to automate the "
            "installation of Titanium Cloud.  Note this utility can only be "
            "used to create configuration files compatible with version " +
            TiS_VERSION + " of Titanium Cloud.\n\n"
            "NOTE: Moving backwards in the wizard will result in loss of the "
            "current page's configuration and will need to be reentered\n\n"
            "Press next to begin.\n\n\n\n")
        help_text.Wrap(TEXT_WIDTH)
        self.add_content(help_text)

        # self.add_line()

        # To implement this, would need special mapping for every page...
        # (from config to control)
        # putting this on the long(er)-term todo list for now
        # self.add_content(wx.StaticText(
        #    self, -1,
        #    'You may optionally pre-populate this utility by reading in an '
        #    'existing Titanium Cloud configuration file'))

        # self.load_button = wx.Button(self, -1, "Load Configuration File "
        #                                       "(Optional)")
        # self.Bind(wx.EVT_BUTTON, self.on_read, self.load_button)
        # self.add_content(self.load_button)

    def on_read(self, event):
        reader = wx.FileDialog(
            self, "Open Existing Titanium Cloud Configuration File",
            "", "", "INI file (*.ini)|*.ini",
            wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)

        if reader.ShowModal() == wx.ID_CANCEL:
            return

        # Read in the config file
        global filename, filedir, config
        try:
            config.read(reader.GetPath())
            filename = reader.GetFilename()
            filedir = reader.GetDirectory()
        except Exception as ex:
            wx.LogError("Cannot parse configuration file, Error: %s." % ex)
            config = configparser.RawConfigParser()
            config.optionxform = str
            return

        # todo tsmith
        # Do validation of the imported file


class REGIONPage(ConfigPage):
    def load(self):
        super(REGIONPage, self).load()

        # Header in INI file
        self.section = "SHARED_SERVICES"
        self.validator_methods = []
        self.title = "Region Configuration"
        self.help_text = (
            "Configuring this system in region mode provides the ability to "
            "operate as a secondary independent region to an existing "
            "Openstack cloud deployment (Certain restrictions apply, refer to "
            "system documentation).\n\n"
            "Keystone (and optionally Glance) "
            "services can be configured as shared services, which "
            "prevents them from being configured on the secondary region and "
            "instead those services already configured in the primary region "
            "will be accessed.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

        # Skip region pages by default
        self.skip_region(True)

    def set_fields(self):
        self.fields['is_region'] = Field(
            text="Configure as a secondary region",
            type=TYPES.checkbox,
            transient=True,
            shows=["REGION_NAME",
                   "ADMIN_TENANT_NAME",
                   "ADMIN_USER_NAME",
                   "ADMIN_PASSWORD",
                   "SERVICE_TENANT_NAME",
                   "keystone_help",
                   "KEYSTONE_ADMINURL",
                   "sep1",
                   "keystone_note",
                   ]
        )

        self.fields['REGION_NAME'] = Field(
            text="Name of the primary region",
            type=TYPES.string,
            initial="RegionOne"
        )
        self.fields["sep1"] = Field(type=TYPES.separator)
        self.fields['keystone_help'] = Field(
            text="Primary Keystone Configuration\n\nThis information "
                 "is needed for the primary "
                 "region in order to validate or create the shared "
                 "services.",
            type=TYPES.help,
        )
        self.fields['SERVICE_TENANT_NAME'] = Field(
            text="Name of the service tenant",
            type=TYPES.string,
            initial="RegionTwo_services"
        )
        self.fields['ADMIN_TENANT_NAME'] = Field(
            text="Name of the admin tenant",
            type=TYPES.string,
            initial="admin"
        )
        self.fields['ADMIN_USER_NAME'] = Field(
            text="Username of the keystone admin account",
            type=TYPES.string,
            initial="admin"
        )
        self.fields['ADMIN_PASSWORD'] = Field(
            text="Password of the keystone admin account",
            type=TYPES.string,
            initial=""
        )
        self.fields['KEYSTONE_ADMINURL'] = Field(
            text="Authentication URL of the keystone service",
            type=TYPES.string,
            initial="http://192.168.204.2:5000/v3"
        )
        self.fields['keystone_note'] = Field(
            text="NOTE: If 'Automatically configure shared keystone' "
                 "is checked in the upcoming 'Secondary Region Services' page,"
                 " then the service tenant (above) will be created "
                 "if not present.",
            type=TYPES.help,
        )

    def validate_page(self):
        super(REGIONPage, self).validate_page()
        # Do page specific validation here
        if self.fields['is_region'].get_value() == 'Y' and \
                not config.has_option(self.section, "ADMIN_PASSWORD"):
            raise ValidateFail("The keystone admin password is mandatory")

    def get_config(self):
        super(REGIONPage, self).get_config()

        if len(config.items(self.section)) == 0:
            config.remove_section(self.section)
            config.remove_section("REGION_2_SERVICES")
            config.remove_section("REGION2_PXEBOOT_NETWORK")
        else:
            # Add service name which doesn't change
            config.set(self.section, "KEYSTONE_SERVICE_NAME", "keystone")
            config.set(self.section, "KEYSTONE_SERVICE_TYPE", "identity")

    def bind_events(self):
        self.fields['is_region'].input.Bind(wx.EVT_CHECKBOX, self.on_region)

    def on_region(self, event):
        # Set the region pages to be skipped or not
        self.skip_region(event.GetInt() == 0)
        event.Skip()

    def skip_region(self, skip):
        debug("Setting region skips to %s" % skip)
        self.next.skip = skip
        self.next.next.skip = skip
        self.next.next.next.skip = skip
        self.parent.skip_page(AUTHPage, not skip)

        # Set the config type appropriately
        global CONFIG_TYPE
        if skip:
            CONFIG_TYPE = DEFAULT_CONFIG
        else:
            CONFIG_TYPE = REGION_CONFIG

        # Remove any sections that aren't handled in region-config mode
        config.remove_section("PXEBOOT_NETWORK")
        config.remove_section("AUTHENTICATION")


class SHAREDSERVICESPage(ConfigPage):
    def load(self):
        super(SHAREDSERVICESPage, self).load()

        self.section = "SHARED_SERVICES"
        self.validator_methods = []
        self.title = "Regions - Shared Services"
        self.help_text = (
            "Keystone is always configured as a shared service.  "
            "Glance may also optionally be configured as "
            "shared services.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        # GLANCE
        self.fields['share_glance'] = Field(
            text="Share the primary region's glance service",
            type=TYPES.checkbox,
            transient=True
        )

    def validate_page(self):
        # do previous pages validation as well to refresh config, since they
        # share a section
        self.prev.validate_page()
        super(SHAREDSERVICESPage, self).validate_page()

        # Do page specific validation here

    def get_config(self):
        # Skip the parent get_config so the section isn't removed
        # (since it's shared we want the old info)
        self.add_fields()

        # Add Static service types
        if self.fields['share_glance'].get_value() == 'Y':
            config.set(self.section, "GLANCE_SERVICE_NAME", "glance")
            config.set(self.section, "GLANCE_SERVICE_TYPE", "image")


class REG2SERVICESPage(ConfigPage):

    def load(self):
        super(REG2SERVICESPage, self).load()
        self.section = "REGION_2_SERVICES"
        # Validation is only done on last of region pages
        self.validator_methods = []
        self.title = "Secondary Region Services (1/2)"
        self.help_text = (
            "Secondary region services are not shared with the primary "
            "region, during installation they will be configured to run "
            "in this region.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):

        self.fields['create_help'] = Field(
            text="During configuration, the Primary Region's Keystone "
                 "can be automatically "
                 "provisioned to accommodate this region, including if "
                 "necessary the services tenant, users, services, "
                 "and endpoints.  If this is not "
                 "enabled, manual configuration of the Primary Region's "
                 "Keystone must be done and "
                 "only validation will be performed during this secondary "
                 "region's configuration.\n\n"
                 "Note: passwords are optional if this option is selected.",
            type=TYPES.help,
        )
        self.fields['CREATE'] = Field(
            text="Automatically configure shared keystone",
            type=TYPES.checkbox,
            initial='Y',
        )
        self.fields['REGION_NAME'] = Field(
            text="Name for this system's region",
            type=TYPES.string,
            initial="RegionTwo"
        )
        self.fields['sep1'] = Field(type=TYPES.separator)

        if not config.has_option('SHARED_SERVICES', 'GLANCE_SERVICE_NAME'):
            # GLANCE
            self.fields['GLANCE_USER_NAME'] = Field(
                text="Glance username",
                type=TYPES.string,
                initial="glance")
            self.fields['GLANCE_PASSWORD'] = Field(
                text="Glance user password",
                type=TYPES.string,
                initial="")
            self.fields['sep2'] = Field(type=TYPES.separator)

        self.fields['NOVA_USER_NAME'] = Field(
            text="Nova username",
            type=TYPES.string, initial="nova")
        self.fields['NOVA_PASSWORD'] = Field(
            text="Nova user password",
            type=TYPES.string, initial="")

    def validate_page(self):
        super(REG2SERVICESPage, self).validate_page()

        if self.fields['CREATE'].get_value() == 'N':
            if (('GLANCE_PASSWORD' in self.fields and
                    not self.fields['GLANCE_PASSWORD'].get_value()) or
                    not self.fields['NOVA_PASSWORD'].get_value()):
                raise ValidateFail("Passwords are mandatory when automatic "
                                   "keystone configuration is not enabled.")

    def get_config(self):
        super(REG2SERVICESPage, self).get_config()


class REG2SERVICESPage2(ConfigPage):

    def load(self):
        super(REG2SERVICESPage2, self).load()

        self.section = "REGION_2_SERVICES"
        # Validation is only done on last page
        self.validator_methods = ["validate_network", "validate_region"]
        self.title = "Secondary Region Services (2/2)"

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        self.fields['NEUTRON_USER_NAME'] = Field(
            text="Neutron username",
            type=TYPES.string, initial="neutron")
        self.fields['NEUTRON_PASSWORD'] = Field(
            text="Neutron user password",
            type=TYPES.string, initial="")

        self.fields['SYSINV_USER_NAME'] = Field(
            text="Sysinv username",
            type=TYPES.string, initial="sysinv")
        self.fields['SYSINV_PASSWORD'] = Field(
            text="Sysinv user password",
            type=TYPES.string, initial="")

        self.fields['PATCHING_USER_NAME'] = Field(
            text="Patching username",
            type=TYPES.string, initial="patching")
        self.fields['PATCHING_PASSWORD'] = Field(
            text="Patching user password",
            type=TYPES.string, initial="")

        self.fields['HEAT_USER_NAME'] = Field(
            text="Heat username",
            type=TYPES.string, initial="heat")
        self.fields['HEAT_PASSWORD'] = Field(
            text="Heat user password",
            type=TYPES.string, initial="")
        self.fields['HEAT_ADMIN_DOMAIN'] = Field(
            text="Heat admin domain",
            type=TYPES.string, initial="heat")
        self.fields['HEAT_ADMIN_USER_NAME'] = Field(
            text="Heat admin username",
            type=TYPES.string, initial="heat_stack_admin")
        self.fields['HEAT_ADMIN_PASSWORD'] = Field(
            text="Password of the heat admin user",
            type=TYPES.string, initial="")

        self.fields['CEILOMETER_USER_NAME'] = Field(
            text="Ceilometer username",
            type=TYPES.string, initial="ceilometer")
        self.fields['CEILOMETER_PASSWORD'] = Field(
            text="Ceilometer user password",
            type=TYPES.string, initial="")

        self.fields['AODH_USER_NAME'] = Field(
            text="Aodh username",
            type=TYPES.string, initial="aodh")
        self.fields['AODH_PASSWORD'] = Field(
            text="Aodh user password",
            type=TYPES.string, initial="")

        self.fields['NFV_USER_NAME'] = Field(
            text="NFV username",
            type=TYPES.string, initial="vim")
        self.fields['NFV_PASSWORD'] = Field(
            text="NFV user password",
            type=TYPES.string, initial="")

        self.fields['MTCE_USER_NAME'] = Field(
            text="MTCE username",
            type=TYPES.string, initial="mtce")
        self.fields['MTCE_PASSWORD'] = Field(
            text="MTCE user password",
            type=TYPES.string, initial="")

        self.fields['PANKO_USER_NAME'] = Field(
            text="PANKO username",
            type=TYPES.string, initial="panko")
        self.fields['PANKO_PASSWORD'] = Field(
            text="PANKO user password",
            type=TYPES.string, initial="")

        self.fields['PLACEMENT_USER_NAME'] = Field(
            text="Placement username",
            type=TYPES.string, initial="placement")
        self.fields['PLACEMENT_PASSWORD'] = Field(
            text="Placement user password",
            type=TYPES.string, initial="")

        self.fields['GNOCCHI_USER_NAME'] = Field(
            text="GNOCCHI username",
            type=TYPES.string, initial="gnocchi")
        self.fields['GNOCCHI_PASSWORD'] = Field(
            text="GNOCCHI user password",
            type=TYPES.string, initial="")

        self.fields['FM_USER_NAME'] = Field(
            text="FM username",
            type=TYPES.string, initial="fm")
        self.fields['FM_PASSWORD'] = Field(
            text="FM user password",
            type=TYPES.string, initial="")

        self.fields['BARBICAN_USER_NAME'] = Field(
            text="Barbican username",
            type=TYPES.string, initial="barbican")
        self.fields['BARBICAN_PASSWORD'] = Field(
            text="Barbican user password",
            type=TYPES.string, initial="")

    def validate_page(self):
        self.prev.validate_page()
        super(REG2SERVICESPage2, self).validate_page()

    def get_config(self):
        # Special handling for all region sections is done here
        self.add_fields()


class SYSTEMPage(ConfigPage):
    def load(self):
        super(SYSTEMPage, self).load()

        self.section = "SYSTEM"
        self.validator_methods = []
        self.title = "System"
        self.help_text = (
            "All-in-one System Mode Configuration\n\nAvailable options are: \n"
            "duplex-direct: two node redundant configuration. Management and "
            "infrastructure networks are directly connected to peer ports\n"
            "duplex: two node redundant configuration\n"
            "simplex: single node non-redundant configuration")

        self.system_mode = ['duplex-direct', 'duplex', 'simplex']

        self.set_fields()
        self.do_setup()
        self.bind_events()

        self.skip_not_required_pages(False)

    def set_fields(self):
        self.fields['use_mode'] = Field(
            text="Configure as an All-in-one system",
            type=TYPES.checkbox,
            transient=True,
            shows=["SYSTEM_MODE"]
        )
        self.fields['SYSTEM_MODE'] = Field(
            text="System redundant configuration",
            type=TYPES.radio,
            choices=self.system_mode,
        )

    def validate_page(self):
        super(SYSTEMPage, self).validate_page()

    def get_config(self):
        super(SYSTEMPage, self).get_config()
        if len(config.items(self.section)) == 0:
            config.remove_section(self.section)
        else:
            config.set(self.section, 'SYSTEM_TYPE', 'All-in-one')

    def bind_events(self):
        self.fields['SYSTEM_MODE'].input.Bind(wx.EVT_RADIOBOX, self.on_mode)
        self.fields['use_mode'].input.Bind(wx.EVT_CHECKBOX, self.on_use_mode)

    def on_mode(self, event):
        # Set the pages to be skipped or not
        self.skip_not_required_pages(
            self.system_mode[event.GetInt()] == 'simplex')
        event.Skip()

    def on_use_mode(self, event):
        # Set the pages to be skipped or not
        if event.GetInt() == 0:
            # If set to not in use, ensure the pages are not skipped
            self.skip_not_required_pages(False)
            # And reset to the default selection
            self.fields['SYSTEM_MODE'].set_value('duplex-direct')
        event.Skip()

    def skip_not_required_pages(self, skip):
        # Skip PXEBOOT, BMC and INFRA pages
        self.parent.skip_page(PXEBootPage, skip)
        self.parent.skip_page(INFRAPage, skip)

        # Remove the sections that are not required
        config.remove_section("PXEBOOT_NETWORK")
        config.remove_section("BOARD_MANAGEMENT_NETWORK")
        config.remove_section("INFRA_NETWORK")


class PXEBootPage(ConfigPage):

    def load(self):
        super(PXEBootPage, self).load()
        self.section = "PXEBOOT_NETWORK"
        self.validator_methods = ["validate_pxeboot"]
        self.title = "PXEBoot Network"
        self.help_text = (
            "The PXEBoot network is used for initial booting and installation "
            "of each node. IP addresses on this network are reachable only "
            "within the data center.\n\n"
            "The default configuration combines the PXEBoot network and the "
            "management network. If a separate PXEBoot network is used, it "
            "will share the management interface, which requires the "
            "management network to be placed on a VLAN.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        if config.has_section("REGION_2_SERVICES"):
            self.fields['mandatory'] = Field(
                text="A PXEBoot network is mandatory for secondary"
                     " region deployments.",
                type=TYPES.help
            )
            self.section = "REGION2_PXEBOOT_NETWORK"
        else:
            self.fields['use_pxe'] = Field(
                text="Configure a separate PXEBoot network",
                type=TYPES.checkbox,
                transient=True,
                shows=["PXEBOOT_CIDR", "use_entire_subnet"]
            )
        self.fields['PXEBOOT_CIDR'] = Field(
            text="PXEBoot subnet",
            type=TYPES.string,
            initial="192.168.202.0/24"
        )

        # Start/end ranges
        self.fields['use_entire_subnet'] = Field(
            text="Restrict PXEBoot subnet address range",
            type=TYPES.checkbox,
            shows=["IP_START_ADDRESS", "IP_END_ADDRESS"],
            transient=True
        )
        self.fields['IP_START_ADDRESS'] = Field(
            text="PXEBoot network start address",
            type=TYPES.string,
            initial="192.168.202.2",
        )
        self.fields['IP_END_ADDRESS'] = Field(
            text="PXEBoot network end address",
            type=TYPES.string,
            initial="192.168.202.254",
        )

    def get_config(self):
        super(PXEBootPage, self).get_config()

        if len(config.items(self.section)) == 0:
            config.remove_section(self.section)
            if config.has_section("REGION_2_SERVICES"):
                raise ValidateFail(
                    "Must configure a PXEBoot network when in region mode")

    def validate_page(self):
        super(PXEBootPage, self).validate_page()
        # Do page specific validation here


class MGMTPage(ConfigPage):

    def load(self):
        super(MGMTPage, self).load()

        # Preserve order plus allow mapping back to raw value
        if get_opt('SYSTEM', 'SYSTEM_MODE') == 'duplex-direct':
            self.lag_choices = OrderedDict([
                ('802.3ad (LACP) policy', '4'),
            ])
        else:
            self.lag_choices = OrderedDict([
                ('Active-backup policy', '1'),
                ('802.3ad (LACP) policy', '4'),
            ])
        self.mgmt_speed_choices = [LINK_SPEED_1G,
                                   LINK_SPEED_10G,
                                   LINK_SPEED_25G]
        self.section = "MGMT_NETWORK"
        if get_opt('SYSTEM', 'SYSTEM_MODE') != 'simplex':
            self.validator_methods = ["validate_pxeboot", "validate_mgmt"]
            self.help_text = (
                "The management network is used for internal communication "
                "between platform components. IP addresses on this network "
                "are reachable only within the data center.")
        else:
            self.validator_methods = ["validate_aio_simplex_mgmt"]
            self.help_text = (
                "The management network is used for internal communication "
                "between platform components. IP addresses on this network "
                "are reachable only within the host.")
        self.title = "Management Network"

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        if get_opt('SYSTEM', 'SYSTEM_MODE') != 'simplex':
            self.fields['mgmt_port1'] = Field(
                text="Management interface",
                type=TYPES.string,
                initial="enp0s8",
                transient=True
            )
            self.fields['lag_help'] = Field(
                text="A management bond interface provides redundant "
                     "connections for the management network.  When selected, "
                     "the field above specifies the first member of the bond.",
                type=TYPES.help,
            )
            self.fields['LAG_INTERFACE'] = Field(
                text="Use management interface link aggregation",
                type=TYPES.checkbox,
                shows=["LAG_MODE", "mgmt_port2"],
                transient=True
            )
            self.fields['LAG_MODE'] = Field(
                text="Management interface bonding policy",
                type=TYPES.choice,
                choices=self.lag_choices.keys(),
                transient=True
            )
            self.fields['mgmt_port2'] = Field(
                text="Second management interface member",
                type=TYPES.string,
                initial="",
                transient=True
            )
            self.fields['INTERFACE_MTU'] = Field(
                text="Management interface MTU",
                type=TYPES.int,
                initial="1500",
                transient=True
            )
            self.fields['INTERFACE_LINK_CAPACITY'] = Field(
                text="Management interface link capacity Mbps",
                type=TYPES.choice,
                choices=self.mgmt_speed_choices,
                initial=self.mgmt_speed_choices[0],
                transient=True
            )
            if config.has_option('PXEBOOT_NETWORK', 'PXEBOOT_CIDR') or \
                    config.has_option('REGION2_PXEBOOT_NETWORK',
                                      'PXEBOOT_CIDR'):
                self.fields['vlan_help'] = Field(
                    text=("A management VLAN is required because a separate "
                          "PXEBoot network was configured on the management "
                          "interface."),
                    type=TYPES.help
                )
                self.fields['VLAN'] = Field(
                    text="Management VLAN Identifier",
                    type=TYPES.int,
                    initial="",
                )

            self.fields['CIDR'] = Field(
                text="Management subnet",
                type=TYPES.string,
                initial="192.168.204.0/24",
            )

            self.fields['MULTICAST_CIDR'] = Field(
                text="Management multicast subnet",
                type=TYPES.string,
                initial='239.1.1.0/28'
            )

            # Start/end ranges
            self.fields['use_entire_subnet'] = Field(
                text="Restrict management subnet address range",
                type=TYPES.checkbox,
                shows=["IP_START_ADDRESS", "IP_END_ADDRESS"],
                transient=True
            )
            self.fields['IP_START_ADDRESS'] = Field(
                text="Management network start address",
                type=TYPES.string,
                initial="192.168.204.2",
            )
            self.fields['IP_END_ADDRESS'] = Field(
                text="Management network end address",
                type=TYPES.string,
                initial="192.168.204.254",
            )

            # Dynamic addressing
            self.fields['dynamic_help'] = Field(
                text=(
                    "IP addresses can be assigned to hosts dynamically or "
                    "a static IP address can be specified for each host. "
                    "Note: This choice applies to both the management network "
                    "and infrastructure network."),
                type=TYPES.help,
            )
            self.fields['DYNAMIC_ALLOCATION'] = Field(
                text="Use dynamic IP address allocation",
                type=TYPES.checkbox,
                initial='Y'
            )
        else:
            self.fields['CIDR'] = Field(
                text="Management subnet",
                type=TYPES.string,
                initial="192.168.204.0/28",
            )

    def validate_page(self):
        super(MGMTPage, self).validate_page()
        # Do page specific validation here

    def get_config(self):
        super(MGMTPage, self).get_config()

        if get_opt('SYSTEM', 'SYSTEM_MODE') != 'simplex':
            # Add logical interface
            ports = self.fields['mgmt_port1'].get_value()
            if self.fields['mgmt_port2'].get_value():
                ports += "," + self.fields['mgmt_port2'].get_value()
            li = create_li(
                lag=self.fields['LAG_INTERFACE'].get_value(),
                mode=self.lag_choices.get(self.fields['LAG_MODE'].get_value()),
                mtu=self.fields['INTERFACE_MTU'].get_value(),
                link_capacity=self.fields[
                    'INTERFACE_LINK_CAPACITY'].get_value(),
                ports=ports
            )
            config.set(self.section, 'LOGICAL_INTERFACE', li)
            clean_lis()


class INFRAPage(ConfigPage):
    def load(self):
        super(INFRAPage, self).load()

        # Preserve order plus allow mapping back to raw value
        self.lag_choices = OrderedDict([
            ('Active-backup policy', '1'),
            ('Balanced XOR policy', '2'),
            ('802.3ad (LACP) policy', '4'),
        ])
        self.infra_speed_choices = [LINK_SPEED_1G,
                                    LINK_SPEED_10G,
                                    LINK_SPEED_25G]

        self.section = "INFRA_NETWORK"
        self.validator_methods = ["validate_storage",
                                  "validate_pxeboot",
                                  "validate_mgmt",
                                  "validate_infra"]
        self.title = "Infrastructure Network"
        self.help_text = (
            "The infrastructure network is used for internal communication "
            "between platform components to offload the management network "
            "of high bandwidth services. "
            "IP addresses on this network are reachable only within the data "
            "center.\n\n"
            "If a separate infrastructure interface is not configured the "
            "management network will be used.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        self.fields['use_infra'] = Field(
            text="Configure an infrastructure interface",
            type=TYPES.checkbox,
            transient=True
        )
        self.fields['infra_port1'] = Field(
            text="Infrastructure interface",
            type=TYPES.string,
            initial="",
            transient=True
        )
        self.fields['lag_help'] = Field(
            text="An infrastructure bond interface provides redundant "
                 "connections for the infrastructure network.  When selected, "
                 "the field above specifies the first member of the bond.",
            type=TYPES.help,
        )
        self.fields['LAG_INTERFACE'] = Field(
            text="Use infrastructure interface link aggregation",
            type=TYPES.checkbox,
            shows=["LAG_MODE", "infra_port2"],
            transient=True
        )
        self.fields['LAG_MODE'] = Field(
            text="Infrastructure interface bonding policy",
            type=TYPES.choice,
            choices=self.lag_choices.keys(),
            transient=True
        )
        self.fields['infra_port2'] = Field(
            text="Second infrastructure interface member",
            type=TYPES.string,
            initial="",
            transient=True
        )
        self.fields['INTERFACE_MTU'] = Field(
            text="Infrastructure interface MTU",
            type=TYPES.int,
            initial="1500",
            transient=True
        )
        self.fields['INTERFACE_LINK_CAPACITY'] = Field(
            text="Infrastructure interface link capacity Mbps",
            type=TYPES.choice,
            choices=self.infra_speed_choices,
            initial=self.infra_speed_choices[-1],
            transient=True
        )

        # VLAN
        self.fields['use_vlan'] = Field(
            text="Configure an infrastructure VLAN",
            type=TYPES.checkbox,
            shows=["VLAN"],
            transient=True
        )
        self.fields['VLAN'] = Field(
            text="Infrastructure VLAN Identifier",
            type=TYPES.int,
            initial="",
        )

        self.fields['CIDR'] = Field(
            text="Infrastructure subnet",
            type=TYPES.string,
            initial="192.168.205.0/24",
        )

        # Start/end ranges
        self.fields['use_entire_subnet'] = Field(
            text="Restrict infrastructure subnet address range",
            type=TYPES.checkbox,
            shows=["IP_START_ADDRESS", "IP_END_ADDRESS"],
            transient=True
        )
        self.fields['IP_START_ADDRESS'] = Field(
            text="Infrastructure network start address",
            type=TYPES.string,
            initial="192.168.205.2",
        )
        self.fields['IP_END_ADDRESS'] = Field(
            text="Infrastructure network end address",
            type=TYPES.string,
            initial="192.168.205.254",
        )

        # This field show/hides all other fields
        self.fields['use_infra'].shows = [field for field in self.fields.keys()
                                          if field is not 'use_infra']

    def validate_page(self):
        super(INFRAPage, self).validate_page()

    def get_config(self):
        if self.fields['use_infra'].get_value() is 'N':
            if config.has_section(self.section):
                config.remove_section(self.section)
            clean_lis()
            return

        super(INFRAPage, self).get_config()

        # Add logical interface
        ports = self.fields['infra_port1'].get_value()
        if self.fields['infra_port2'].get_value():
            ports += "," + self.fields['infra_port2'].get_value()
        li = create_li(
            lag=self.fields['LAG_INTERFACE'].get_value(),
            mode=self.lag_choices.get(self.fields['LAG_MODE'].get_value()),
            mtu=self.fields['INTERFACE_MTU'].get_value(),
            link_capacity=self.fields['INTERFACE_LINK_CAPACITY'].get_value(),
            ports=ports
        )
        config.set(self.section, 'LOGICAL_INTERFACE', li)
        clean_lis()

        if len(config.items(self.section)) == 0:
            config.remove_section(self.section)


class OAMPage(ConfigPage):
    def load(self):
        super(OAMPage, self).load()

        self.lag_choices = OrderedDict([
            ('Active-backup policy', '1'),
            ('Balanced XOR policy', '2'),
            ('802.3ad (LACP) policy', '4'),
        ])

        self.section = "OAM_NETWORK"
        if get_opt('SYSTEM', 'SYSTEM_MODE') == 'simplex':
            self.simplex = True
            self.validator_methods = ["validate_aio_network"]
        else:
            self.simplex = False
            self.validator_methods = ["validate_pxeboot",
                                      "validate_mgmt",
                                      "validate_infra",
                                      "validate_oam"]
        self.title = "External OAM Network"
        self.help_text = (
            "The external OAM network is used for management of the "
            "cloud. It also provides access to the "
            "platform APIs. IP addresses on this network are reachable "
            "outside the data center.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        self.fields['oam_port1'] = Field(
            text="External OAM interface",
            type=TYPES.string,
            initial="enp0s3",
            transient=True
        )
        self.fields['lag_help'] = Field(
            text="An external OAM bond interface provides redundant "
                 "connections for the OAM network.  When selected, the "
                 "field above specifies the first member of the bond.",
            type=TYPES.help,
        )
        self.fields['LAG_INTERFACE'] = Field(
            text="External OAM interface link aggregation",
            type=TYPES.checkbox,
            shows=["LAG_MODE", "oam_port2"],
            transient=True
        )
        self.fields['LAG_MODE'] = Field(
            text="OAM interface bonding policy",
            type=TYPES.choice,
            choices=self.lag_choices.keys(),
            transient=True
        )
        self.fields['oam_port2'] = Field(
            text="Second External OAM interface member",
            type=TYPES.string,
            initial="",
            transient=True
        )
        self.fields['INTERFACE_MTU'] = Field(
            text="External OAM interface MTU",
            type=TYPES.int,
            initial="1500",
            transient=True
        )

        # VLAN
        self.fields['use_vlan'] = Field(
            text="Configure an External OAM VLAN",
            type=TYPES.checkbox,
            shows=["VLAN"],
            transient=True
        )
        self.fields['VLAN'] = Field(
            text="External OAM VLAN Identifier",
            type=TYPES.int,
            initial="",
        )

        self.fields['CIDR'] = Field(
            text="External OAM subnet",
            type=TYPES.string,
            initial="10.10.10.0/24",
        )
        self.fields['GATEWAY'] = Field(
            text="External OAM gateway address",
            type=TYPES.string,
            initial="10.10.10.1",
        )
        if not self.simplex:
            self.fields['IP_FLOATING_ADDRESS'] = Field(
                text="External OAM floating address",
                type=TYPES.string,
                initial="10.10.10.2",
            )
            self.fields['IP_UNIT_0_ADDRESS'] = Field(
                text="External OAM address for first controller node",
                type=TYPES.string,
                initial="10.10.10.3",
            )
            self.fields['IP_UNIT_1_ADDRESS'] = Field(
                text="External OAM address for second controller node",
                type=TYPES.string,
                initial="10.10.10.4",
            )
        else:
            self.fields['IP_ADDRESS'] = Field(
                text="External OAM address",
                type=TYPES.string,
                initial="10.10.10.2",
            )

    def get_config(self):
        super(OAMPage, self).get_config()

        # Add logical interface
        ports = self.fields['oam_port1'].get_value()
        if self.fields['oam_port2'].get_value():
            ports += "," + self.fields['oam_port2'].get_value()
        li = create_li(
            lag=self.fields['LAG_INTERFACE'].get_value(),
            mode=self.lag_choices.get(self.fields['LAG_MODE'].get_value()),
            mtu=self.fields['INTERFACE_MTU'].get_value(),
            ports=ports
        )
        config.set(self.section, 'LOGICAL_INTERFACE', li)
        clean_lis()

    def validate_page(self):
        super(OAMPage, self).validate_page()
        # Do page specific validation here


class AUTHPage(ConfigPage):
    def load(self):
        super(AUTHPage, self).load()
        self.section = "AUTHENTICATION"
        self.validator_methods = ["validate_authentication"]
        self.title = "Authentication"
        self.help_text = (
            "Create the admin user password.\n"
            "It must have a minimum length of 7 characters, and must "
            "contain at least 1 upper case, 1 lower case, 1 digit, "
            "and 1 special character.\n\n"
            "Note: This password will be stored as plaintext in the generated "
            "INI file.")

        self.set_fields()
        self.do_setup()
        self.bind_events()

    def set_fields(self):
        self.fields['ADMIN_PASSWORD'] = Field(
            text="Password",
            type=TYPES.string,
        )

    def get_config(self):
        super(AUTHPage, self).get_config()

    def validate_page(self):
        super(AUTHPage, self).validate_page()
        # Do page specific validation here


class ENDPage(WizardPage):
    # Final page for file saving
    def load(self):
        super(ENDPage, self).load()
        # Must ensure fields are destroyed/don't exist before adding to
        # prevent double-loading
        self.sizer.Clear(True)

        self.set_title("Configuration Complete")
        self.add_content(
            wx.StaticText(self, -1, 'Titanium Cloud Configuration is '
                                    'complete, configuration file may now be '
                                    'saved.'))

        self.write_button = wx.Button(self, -1, "Save Configuration File")
        self.Bind(wx.EVT_BUTTON, self.on_save, self.write_button)
        self.add_content(self.write_button)

        # Add the version to the config
        if not config.has_section("VERSION"):
            config.add_section("VERSION")
        config.set("VERSION", "RELEASE", TiS_VERSION)

        self.preview = wx.TextCtrl(self, -1, value=get_config(),
                                   style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.add_content(self.preview, 3)

    def on_save(self, event):
        writer = wx.FileDialog(self,
                               message="Save Configuration File",
                               defaultDir=filedir or "",
                               defaultFile=filename or "TiC_config.ini",
                               wildcard="INI file (*.ini)|*.ini",
                               style=wx.FD_SAVE,
                               )

        if writer.ShowModal() == wx.ID_CANCEL:
            return

        # Write the configuration to disk
        try:
            with open(writer.GetPath(), "wb") as f:
                config.write(f)
        except IOError:
            wx.LogError("Error writing configuration file '%s'." %
                        writer.GetPath())


# todo tsmith include a 'reformat' to shuffle numbers down?
def clean_lis():
    # Remove unreferenced Logical Interfaces in the config
    referenced = []
    for sec in config.sections():
        if config.has_option(sec, 'LOGICAL_INTERFACE'):
            referenced.append(config.get(sec, 'LOGICAL_INTERFACE'))

    for sec in config.sections():
        if "LOGICAL_INTERFACE_" in sec and sec not in referenced:
            config.remove_section(sec)


def create_li(lag='N', mode=None, mtu=1500, link_capacity=None, ports=None):
    # todo more graceful matching to an existing LI
    for number in range(1, len(config.sections())):
        if config.has_section("LOGICAL_INTERFACE_" + str(number)):
            debug("Found interface " + str(number) + " with ports " +
                  config.get("LOGICAL_INTERFACE_" + str(number),
                             'INTERFACE_PORTS')
                  + ".  Searching for ports: " + ports)
            if config.get("LOGICAL_INTERFACE_" + str(number),
                          'INTERFACE_PORTS') == ports:
                debug("Matched to LI: " + str(number))

                # This logical interface already exists,
                # so use that but update any values
                name = "LOGICAL_INTERFACE_" + str(number)
                config.set(name, 'LAG_INTERFACE', lag)
                if mode:
                    config.set(name, 'LAG_MODE', mode)
                config.set(name, 'INTERFACE_MTU', mtu)
                if link_capacity:
                    config.set(name, 'INTERFACE_LINK_CAPACITY', link_capacity)
                return name

    # Get unused LI number
    number = 1
    while config.has_section("LOGICAL_INTERFACE_" + str(number)):
        number += 1

    # LI doesnt exist so create it with the given values
    name = "LOGICAL_INTERFACE_" + str(number)
    config.add_section(name)
    config.set(name, 'LAG_INTERFACE', lag)
    if mode:
        config.set(name, 'LAG_MODE', mode)
    config.set(name, 'INTERFACE_MTU', mtu)
    if link_capacity:
        config.set(name, 'INTERFACE_LINK_CAPACITY', link_capacity)
    config.set(name, 'INTERFACE_PORTS', ports)
    return name


def main():
    app = wx.App(0)  # Start the application

    # Create wizard and add the pages to it
    conf_wizard = ConfigWizard()

    # Start the wizard
    conf_wizard.run()

    # Cleanup
    conf_wizard.Destroy()
    app.MainLoop()


if __name__ == '__main__':
    main()
