"""
Copyright (c) 2016 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from setuptools import setup, find_packages

setup(
    name='configutilities',
    description='Configuration File Validator',
    version='3.0.1',
    license='Apache-2.0',
    platforms=['any'],
    provides=['configutilities'],
    packages=find_packages(),
    install_requires=['netaddr>=0.7.14'],
    package_data={},
    include_package_data=False,
    entry_points={
        'console_scripts': [
            'config_validator = configutilities.config_validator:main',
        ],
    }
)
