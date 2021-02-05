# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Base test code to test migration scripts
First, focus on the migration script name validation
Second, the validation script sequence call
"""

from mockproc import mockprocess
from os import listdir
from os.path import isfile
from os.path import join
from tempfile import mkdtemp

import os
import unittest

from controllerconfig.upgrades import utils


# The way to assert is to pass a script execution that writes the script file
# name into a file
# The content of the file will contain the sequence of the called scripts
script_body = '''#! /usr/bin/env python
with open('%s', 'a+') as f:
    f.write("%s")
'''

from_release = "20.06"
to_release = "20.12"
action = "migrate"

# Lists to add scripts to be called, use a ":" separator for
# parsing/asserting
validScripts1 = ["71-bla1-bla2-bla3.sh", "8-bla1-bla2-bla3.py:",
                 "21-bla1-bla2-bla3.sh:"]

validScripts2 = ["75-deployment-ns-upgrade.py:", "65-k8s-app-upgrade.sh:",
                 "10-sysinv-adjust-partitions.py:",
                 "60-helm-releases-data-migration.py:",
                 "55-armada-helm-upgrade.py:",
                 "95-apply-mandatory-psp-policies.py:",
                 "10-sysinv-adjust-partitions.py:",
                 "85-update-sc-admin-endpoint-cert.py:",
                 "70-active-secured-etcd-after-upgrade.sh:",
                 "50-dcmanager-subcloud-status-migration.py:",
                 "45-sysinv-remove-identity-shared-service.py:",
                 "25-coredns-configmap.sh:",
                 "20-exempt-admin-from-lockout.sh:",
                 "115-foo-bar-test-ok.sh:", "299-foo-bar-test-ok.sh:",
                 "2123-foo-bar-test-ok.sh"]

invalidScripts1 = ["70-bla1-bla2-bla3.sh", "7-bla1-bla2-bla3.py:",
                   "20-bla1-bla2-bla3.sh:", "-20-bla1-bla2-bla3.sh"]

invalidScripts2 = ["95-apply-mandatory-psp-policies.py",
                   "10-sysinv-adjust-partitions.py:",
                   "85-update-sc-admin-endpoint-cert.py:",
                   "70_active-secured-etcd-after-upgrade.sh:"]


# Append scripts to be executed according to the passed list
def addScripts(self, scripts, output_filename):
    for script in scripts:
        self.scripts.append(script, returncode=0, script=script_body %
                            (output_filename, script))


# Test with the files under "controllerconfig/upgrade-scripts"
def addRealMigrationScripts(self, output_filename):
    path = os.getcwd() + "/upgrade-scripts"
    for f in listdir(path):
        if isfile(join(path, f)):
            self.scripts.append(f, returncode=0, script=script_body %
                                (output_filename, f))


def assertProperSorted(scripts):
    output = False
    sequence = []
    for script in scripts:
        sequence.append(int(script.split("-")[0]))
    if sorted(sequence) == sequence:
        output = True
    return output


class TestMigrationScripts(unittest.TestCase):

    def setUp(self):
        self.scripts_dir = mkdtemp()
        self.output_filename = mkdtemp() + "/output.txt"
        # Re-create the file for each run
        open(self.output_filename, 'w+').close()
        self.scripts = mockprocess.MockProc(self.scripts_dir)

    def test_migration_scripts_success_1(self):
        addScripts(self, validScripts1, self.output_filename)
        with self.scripts:
            utils.execute_migration_scripts(from_release, to_release, action,
                                            self.scripts_dir)
        with open(self.output_filename, 'r') as f:
            output = str(f.read())
        if(assertProperSorted(output.split(':'))):
            pass

    def test_migration_scripts_success_2(self):
        addScripts(self, validScripts2, self.output_filename)
        with self.scripts:
            utils.execute_migration_scripts(from_release, to_release, action,
                                            self.scripts_dir)
        with open(self.output_filename, 'r') as f:
            output = str(f.read())
        if(assertProperSorted(output.split(':'))):
            pass

    def test_real_migration_scripts(self):
        addRealMigrationScripts(self, self.output_filename)
        with self.scripts:
            utils.execute_migration_scripts(from_release, to_release, action,
                                            self.scripts_dir)
        with open(self.output_filename, 'r') as f:
            output = str(f.read())
        if(assertProperSorted(output.split(':'))):
            pass

    def test_migration_scripts_validation_fail_1(self):
        addScripts(self, invalidScripts1, self.output_filename)
        with self.assertRaises(ValueError):
            with self.scripts:
                utils.execute_migration_scripts(from_release, to_release,
                                                action, self.scripts_dir)

    def test_migration_scripts_validation_fail_2(self):
        addScripts(self, invalidScripts2, self.output_filename)
        with self.assertRaises(ValueError):
            with self.scripts:
                utils.execute_migration_scripts(from_release, to_release,
                                                action, self.scripts_dir)

    def tearDown(self):
        os.remove(self.output_filename)
