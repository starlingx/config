"""
Copyright (c) 2015-2016 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import sys
import os
from six.moves import configparser
from common.validator import validate
from common.configobjects import DEFAULT_CONFIG, REGION_CONFIG
from common.exceptions import ConfigFail, ValidateFail


def parse_config(config_file):
    """Parse system config file"""
    config = configparser.RawConfigParser()
    try:
        config.read(config_file)
    except Exception as e:
        raise ConfigFail("Error parsing system config file: %s" % e.message)
    return config


def show_help():
    print ("Usage: %s\n"
           "Perform validation of a given configuration file\n\n"
           "--system-config <name>   Validate a system configuration file\n"
           "--region-config <name>   Validate a region configuration file\n"
           % sys.argv[0])
    exit(1)


def main():
    config_file = None
    system_config = False
    region_config = False

    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] == "--system-config":
            arg += 1
            if arg < len(sys.argv):
                config_file = sys.argv[arg]
            else:
                print "--system-config requires the filename of the config " \
                      "file"
                exit(1)
            system_config = True
        elif sys.argv[arg] == "--region-config":
            arg += 1
            if arg < len(sys.argv):
                config_file = sys.argv[arg]
            else:
                print "--region-config requires the filename of the config " \
                      "file"
                exit(1)
            region_config = True
        elif sys.argv[arg] in ["--help", "-h", "-?"]:
            show_help()
        else:
            print "Invalid option."
            show_help()
        arg += 1

    if [system_config, region_config].count(True) != 1:
        print "Invalid combination of options selected"
        show_help()

    if system_config:
        config_type = DEFAULT_CONFIG
    else:
        config_type = REGION_CONFIG

    if not os.path.isfile(config_file):
        print("Config file %s does not exist" % config_file)
        exit(1)

    # Parse the system config file
    print "Parsing configuration file... ",
    system_config = parse_config(config_file)
    print "DONE"

    # Validate the system config file
    print "Validating configuration file... ",
    try:
        # we use the presence of tsconfig to determine if we are onboard or
        # not since it will not be available in the offboard case
        offboard = False
        try:
            from tsconfig.tsconfig import SW_VERSION  # noqa: F401
        except ImportError:
            offboard = True
        validate(system_config, config_type, None, offboard)
    except configparser.Error as e:
        print("Error parsing configuration file %s: %s" % (config_file, e))
    except (ConfigFail, ValidateFail) as e:
        print("\nValidation failed: %s" % e)
    print "DONE"
