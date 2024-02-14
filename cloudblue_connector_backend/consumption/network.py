# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-


from cloudblue_connector_backend.consumption.base import AggregatedConsumption


class FloatingIP(AggregatedConsumption):
    resource_type = 'ip_count'
    rate = 1


class OutgoingTraffic(AggregatedConsumption):
    resource_type = 'traffic-out'
    rate = 1024 * 1024 # MB

class IncomingTraffic(AggregatedConsumption):
    resource_type = 'traffic-in'
    rate = 1024 * 1024  # MB
