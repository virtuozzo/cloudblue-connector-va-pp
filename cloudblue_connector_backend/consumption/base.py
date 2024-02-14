# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-

from cloudblue_connector_backend.connector import ConnectorMixin
from cloudblue_connector.core import getLogger

LOG = getLogger("Connector")


class Consumption(ConnectorMixin):
    """Base class for all consumption collectors"""

    def __init__(self):
        self.logger = getLogger(self.__class__.__name__)


class AggregatedConsumption(Consumption):
    resource_type = None
    rate = 1

    def collect_consumption(self, ve_name, start_time, end_time):
        measures = []
        if not self.resource_type:
            return 0
        elif self.resource_type in ['ram', 'storage', 'cpu', 'ip_count']:
            measures = self.pp_client.get_instance_params(name=ve_name)
        elif 'traffic' in self.resource_type:
            measures = self.pva_client.get_network_usage(name=ve_name, start_time=start_time, end_time=end_time)
        elif self.resource_type == 'backup_storage':
            measures = self.pp_client.get_instance_backups_size(ve_name)
        return self.get_value(measures)

    def get_value(self, measures):
        LOG.debug("Resouse type: {}, Measures: {}".format(self.resource_type, measures))
        if self.resource_type == 'traffic-in' and 'inc_bytes' in measures:
            bytes_in = float(measures['inc_bytes'])
            return round(bytes_in / self.rate, 4)
        elif self.resource_type == 'traffic-out' and 'inc_bytes' in measures:
            bytes_out = float(measures['out_bytes'])
            return round(bytes_out / self.rate, 4)
        elif self.resource_type == 'backup_storage':
            backup_size = float(measures['backup_size'])
            return round(backup_size / self.rate, 4)
        elif self.resource_type in measures:
            if self.resource_type in ['ram', 'cpu'] and measures['state'] in ['stopped', 'suspended']:
                return 0
            res = int(measures[self.resource_type])
            return res / self.rate
        else:
            return 0


class Zero(Consumption):
    def collect_consumption(self, *args):
        return 0
