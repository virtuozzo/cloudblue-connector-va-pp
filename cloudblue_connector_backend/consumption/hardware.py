# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-


from cloudblue_connector_backend.consumption.base import AggregatedConsumption


class CPU(AggregatedConsumption):
    resource_type = 'cpu'
    rate = 1


class RAM(AggregatedConsumption):
    resource_type = 'ram'
    rate = 1024


class Storage(AggregatedConsumption):
    resource_type = 'storage'
    rate = 1024


class BackupStorage(AggregatedConsumption):
    resource_type = 'backup_storage'
    rate = 1024 * 1024 * 1024  # GB
