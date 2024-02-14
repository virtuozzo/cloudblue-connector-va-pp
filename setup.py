# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-

from distutils.core import setup
import os.path


def get_version():
    if os.path.isfile('Makefile.version'):
        with open('Makefile.version', 'r') as f:
            return f.read().strip()

setup(
    name='cloudblue_connector_backend',
    version=get_version(),
    packages=[
        'cloudblue_connector_backend',
        'cloudblue_connector_backend.consumption',
        'cloudblue_connector_backend.ppapi',
        'cloudblue_connector_backend.pvamn'
    ],
    scripts=['cloudblue-password-manager', 'cloudblue-subscriptions-cleaner', 'cloudblue-pvamn-cli'],
    long_description=open('README.txt').read(),
)