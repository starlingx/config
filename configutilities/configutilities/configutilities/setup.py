"""
Copyright (c) 2016-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from setuptools import setup
from setuptools import find_packages

setup(
    name='wrs-configutility',
    description='Titanium Cloud Configuration Utility',
    version='3.0.2',
    license='Apache-2.0',
    platforms=['any'],
    provides=['configutilities'],
    packages=find_packages(),
    install_requires=['netaddr>=0.7.14', 'six'],
    package_data={},
    include_package_data=False,
    entry_points={
        'gui_scripts': [
            'config_gui = configutilities.configgui:main',
        ],
        'console_scripts': [
            'config_validator = configutilities.config_validator:main'
        ],
    }
)
