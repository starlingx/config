#
# Copyright (c) 2015-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from setuptools import setup
from setuptools import find_packages

setup(
    name='controllerconfig',
    description='Controller Configuration',
    version='1.0.0',
    license='Apache-2.0',
    platforms=['any'],
    provides=['controllerconfig'],
    packages=find_packages(),
    package_data={},
    include_package_data=False,
    entry_points={
        'console_scripts': [
            'config_controller = controllerconfig.systemconfig:main',
            'config_region = controllerconfig.regionconfig:region_main',
            'config_subcloud = controllerconfig.regionconfig:subcloud_main',
            'config_management = controllerconfig.config_management:main',
            'upgrade_controller = controllerconfig.upgrades.controller:main',
            'upgrade_controller_simplex = '
            'controllerconfig.upgrades.controller:simplex_main',
            'tidy_storage_post_restore = controllerconfig.tidy_storage:main'
        ],
    }
)
