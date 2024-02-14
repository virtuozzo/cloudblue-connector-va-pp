# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-

import copy
import json
import os
import random
import string
import sys
from datetime import datetime
import subprocess
import traceback

from connect.exceptions import FailRequest, SkipRequest
from connect.resources.directory import Directory
from connect.rql import Query

from cloudblue_connector_backend.pvamn.api import AutomatorClient, AutomatorResponseError, AutomatorNotFoundError
from cloudblue_connector_backend.ppapi.api import PowerPanel, PowerPanelResponseError
from connect.config import Config
from connect.models import ActivationTemplateResponse, ActivationTileResponse, UsageFile, Product, Contract

from cloudblue_connector.core import getLogger, ConnectorPasswords
from cloudblue_connector.core.decorators import once, memoize, MISSING

LOG = getLogger("Connector")


class ConnectorConfig(Config):
    """Extension of CloudBlue connect config model"""

    @staticmethod
    def _read_config_value(config, key, default=MISSING):
        if default is MISSING:
            if key not in config:
                raise ValueError('"{}" not found in the config file'.format(key))
        val = config.get(key, default)
        if isinstance(val, dict):
            if default is not MISSING:
                for k in default:
                    if k not in val:
                        val[k] = default[k]
            return val
        return val.encode('utf-8') if not isinstance(val, (str, list, int)) else val

    def __init__(self, **kwargs):
        filename = kwargs.get('file')
        if filename and not os.path.exists(filename):
            LOG.error('Configuration file "%s" not found.', filename)
            sys.exit(1)

        pass_mngr = ConnectorPasswords()
        if filename:
            # read infrastructure parameters
            with open(filename) as config_file:
                config = json.loads(config_file.read())
            self._pva_socket = self._read_config_value(config, 'pva_socket')
            self._pva_host = self._read_config_value(config, 'pva_host', '127.0.0.1')
            self._pva_port = self._read_config_value(config, 'pva_port', 4533)
            self._pva_login = self._read_config_value(config, 'pva_login', 'root')
            self._pva_password = self._read_config_value(config, 'pva_password', 'pva_password')
            # self._pva_host = '127.0.0.1'
            # self._pva_port = 4533
            # self._pva_login = 'root'
            # self._pva_password = 'pva_password'
            self._pva_connect_timeout = self._read_config_value(config, 'pva_connect_timeout')
            self._pva_socket_read_delay = self._read_config_value(config, 'pva_socket_read_delay')
            self._templates = self._read_config_value(config, 'templates', {})
            self._keystone_endpoint = self._read_config_value(config, 'keystone_endpoint')
            self._pp_url = self._read_config_value(config, 'pp_url')
            self._pp_login = self._read_config_value(config, 'pp_login')
            self._pp_password = pass_mngr.pp_password
            self._pp_domain = 'default'
            self._post_hook_script = self._read_config_value(config, 'post_hook_script',
                                                             '/etc/cloudblue-connector/posthook.sh')
            self._post_hook_exec_timeout = self._read_config_value(config, 'post_hook_exec_timeout', 120)
            self._misc = self._read_config_value(
                config, 'misc', {
                    'domainDeleteOnFail': True,
                    'hidePasswordsInLog': True,
                    'testMarketplaceId': None,
                    'testMode': False,
                    'orderRamInMegabytes': False,
                })
            self._report_suspended = self._read_config_value(config, 'report_suspended', True)
            self._data_retention_period = int(self._read_config_value(config, 'dataRetentionPeriod', 15))
            # prepare data for connect
            api_url = self._read_config_value(config, 'apiEndpoint')
            api_key = pass_mngr.cloudblue_api_key
            products = self._read_config_value(config, 'products')
            if kwargs.get('report_usage', False):
                products = self._read_config_value(config, 'report_usage')
            products = [products] if isinstance(products, str) and products else products or []
            super(ConnectorConfig, self).__init__(api_url=api_url, api_key=api_key, products=products)
        else:
            # LOG.error('Configuration file not specified')
            sys.exit(1)

    @property
    def pva_socket(self):
        return self._pva_socket

    @property
    def pva_host(self):
        return self._pva_host

    @property
    def pva_port(self):
        return self._pva_port

    @property
    def pva_login(self):
        return self._pva_login

    @property
    def pva_password(self):
        return self._pva_password

    @property
    def pva_connect_timeout(self):
        return self._pva_connect_timeout

    @property
    def pva_socket_read_delay(self):
        return self._pva_socket_read_delay

    @property
    def keystone_endpoint(self):
        return self._keystone_endpoint

    @property
    def pp_url(self):
        return self._pp_url

    @property
    def pp_login(self):
        return self._pp_login

    @property
    def pp_password(self):
        return self._pp_password

    @property
    def pp_domain(self):
        return self._pp_domain

    @property
    def templates(self):
        return copy.deepcopy(self._templates)

    @property
    def post_hook_script(self):
        return self._post_hook_script

    @property
    def post_hook_exec_timeout(self):
        return self._post_hook_exec_timeout

    @property
    def misc(self):
        return copy.deepcopy(self._misc)

    @property
    def report_suspended(self):
        return self._report_suspended

    @property
    def data_retention_period(self):
        return self._data_retention_period


class ConnectorMixin(object):
    @memoize
    def get_answer(self, product, answer):
        """Get template object specified in the Config"""
        c = Config.get_instance()
        line = c.templates.get(product, {}).get(answer)
        if line is None:
            return line

        if line.startswith('TL'):
            return ActivationTemplateResponse(line)
        return ActivationTileResponse(line)

    @property
    @once
    def pva_client(self):
        c = Config.get_instance()

        if os.path.exists(c.pva_socket):
            client = AutomatorClient(
                unix_socket=c.pva_socket,
                socket_read_delay=c.pva_socket_read_delay,
                socket_connection_timeout=c.pva_connect_timeout
            )
        else:
            client = AutomatorClient(
                address=c.pva_host,
                port=c.pva_port,
                login=c.pva_login,
                password=c.pva_password,
                socket_read_delay=c.pva_socket_read_delay,
                socket_connection_timeout=c.pva_connect_timeout
            )
        return client

    @property
    @once
    def pp_client(self):
        c = Config.get_instance()
        client = PowerPanel(
            pp_url=c.pp_url,
            keystone_endpoint=c.keystone_endpoint,
            login=c.pp_login,
            password=c.pp_password,
            domain=c.pp_domain
        )
        return client

    @property
    def consumptions(self):
        from cloudblue_connector_backend.consumption.hardware import CPU, Storage, RAM, BackupStorage
        from cloudblue_connector_backend.consumption.network import FloatingIP, OutgoingTraffic, IncomingTraffic
        return {
            'CPU_consumption': CPU(),
            'Storage_consumption': Storage(),
            'RAM_consumption': RAM(),
            'Floating_IP_consumption': FloatingIP(),
            'Outgoing_Traffic_consumption': OutgoingTraffic(),
            'Incoming_Traffic_consumption': IncomingTraffic(),
            'Backup_storage_consumption': BackupStorage()
        }

    @property
    def usage_record_search_criteria(self):
        return 'parameter.domain_name'

    def create_or_update_pp_user(self, pp_user, pp_password=None):
        user_id = self.pp_client.get_userid_by_name(pp_user)
        try:
            if user_id and pp_password:
                self.pp_client.update_user_password(pp_user, pp_password)
            elif not user_id:
                if not pp_password:
                    pp_password = self.pwgen()
                user = self.pp_client.create_user(pp_user, pp_password)
                project = self.pp_client.create_project(pp_user)
                if not user and project:
                    project.delete()
                    return False
                elif user and not project:
                    user.delete()
                    return False
                elif not user and not project:
                    return False
                self.pp_client.assign_user_role(user, project)
            return self.pp_client.resume_user(pp_user)
        except PowerPanelResponseError as error:
            LOG.error(traceback.format_exc())
            raise FailRequest(str(error))

    def _get_node_from_pool(self):
        eid = None
        ram_usage = 100.0
        ram_deny_limit = 90.0

        pools = self.pva_client.get_ip_pools_list()

        bindings = []
        for pool in pools:
            for b in pool['bindings']:
                if b not in bindings:
                    bindings.append(b)

        for node in self.pva_client.get_nodes_stat():
            if 'state' in node and node['state'] == "6" \
                    and float(node['memory']) < ram_usage \
                    and float(node['memory']) < ram_deny_limit \
                    and self.pp_client.is_host_exist(node['hostname']) \
                    and node['eid'] in bindings:
                eid = node['eid']
                ram_usage = float(node['memory'])
        return eid

    def sync_migration_domain(self, pp_user, subscription_id, items, ve_uuid):
        conf = Config.get_instance()

        # Get Quotas
        cpu_quota = self.get_quota(items.get('cpu_limit', items.get("cpu_consumption", None)))
        cpu_mhz_quota = self.get_quota(items.get('cpu_mhz_limit', items.get("cpu_consumption", None)))
        ram_quota = self.get_quota(items.get('ram_limit', items.get("ram_consumption", None)))
        if conf.misc['orderRamInMegabytes']:
            ram_quota = float(ram_quota) / 1024
        vol_quota = self.get_quota(items.get('storage_limit', items.get("storage_consumption", None)))
        fip_quota = self.get_quota(items.get('floating_ip_limit', items.get("floating_ip_consumption", None)))

        instances = {ve['uuid']: ve for ve in self.pp_client.get_instances()}
        ve_name = None
        if ve_uuid in instances:
            ve_name = instances[ve_uuid]['sdk_name']

        if not ve_name:
            LOG.error(traceback.format_exc())
            raise FailRequest("VE with uuid: {} not found in PowerPanel, nothing to do".format(ve_uuid))

        ve = self.pva_client.get_ve_info(ve_name)
        ve_state = ve.get('state')
        if ve_state == '6' and not self.pva_client.stop_ve(ve_name):
            raise FailRequest('Failed to start VM:{}'.format(ve_name))
        try:
            do_resize = False
            domain = self.pva_client.update_ve(
                name=ve_name,
                ram=ram_quota,
                cpu_cores=cpu_quota,
                disk_size=vol_quota,
                fip_count=fip_quota,
                cpu_limit_mhz=cpu_mhz_quota,
                resize=do_resize,
                new_name=subscription_id
            )
        except AutomatorResponseError as error:
            if ve_state == '6':
                self.pva_client.start_ve(ve_name)
            LOG.error(traceback.format_exc())
            raise FailRequest(str(error))

        try:
            self.pp_client.assign_ve_to_user(domain['id'], pp_user)
        except Exception as error:
            LOG.error(traceback.format_exc())
            raise FailRequest(str(error))
        if ve_state == '6' and not self.pva_client.start_ve(domain['name']):
            raise FailRequest('Failed to start VM:{}'.format(domain['name']))

        return domain

    def create_or_update_domain(self, pp_user, subscription_id, ve_hostname, ve_password, os_template, items):
        conf = Config.get_instance()

        # Get Quotas
        cpu_quota = self.get_quota(items.get('cpu_limit', items.get("cpu_consumption", None)))
        cpu_mhz_quota = self.get_quota(items.get('cpu_mhz_limit', items.get("cpu_consumption", None)))
        ram_quota = self.get_quota(items.get('ram_limit', items.get("ram_consumption", None)))
        if conf.misc['orderRamInMegabytes']:
            ram_quota = float(ram_quota) / 1024
        vol_quota = self.get_quota(items.get('storage_limit', items.get("storage_consumption", None)))
        fip_quota = self.get_quota(items.get('floating_ip_limit', items.get("floating_ip_consumption", None)))

        ve_exist = self.pva_client.ve_exist(subscription_id)
        LOG.debug("VE exist {}".format(ve_exist))
        if not ve_exist:
            try:
                # Get Hypervisor uuid:
                host_uuid = self._get_node_from_pool()
                LOG.debug("Trying to create VM {}, HOSTNAME: {}, TEMPLATE: {}, HOST: {}".format(
                    subscription_id, ve_hostname, os_template, host_uuid))
                # create VM
                self.pva_client.create_ve(
                    name=subscription_id,
                    hostname=ve_hostname,
                    os_template=os_template,
                    host_uuid=host_uuid

                )
            except AutomatorResponseError as error:
                LOG.error(traceback.format_exc())
                raise FailRequest(str(error))

        ve = self.pva_client.get_ve_info(subscription_id)
        ve_state = ve.get('state')
        try:
            do_resize = False
            if not ve_exist:
                do_resize = True
            domain = self.pva_client.update_ve(
                name=subscription_id,
                ram=ram_quota,
                cpu_cores=cpu_quota,
                disk_size=vol_quota,
                fip_count=fip_quota,
                cpu_limit_mhz=cpu_mhz_quota,
                resize=do_resize
            )
        except AutomatorResponseError as error:
            if ve_state == '6':
                self.pva_client.start_ve(subscription_id)
            LOG.error(traceback.format_exc())
            raise FailRequest(str(error))

        try:
            self.pp_client.assign_ve_to_user(domain['id'], pp_user)
        except Exception as error:
            LOG.error(traceback.format_exc())
            raise FailRequest(str(error))
        if not self.pva_client.start_ve(domain['name']):
            raise FailRequest('Failed to start VM:{}'.format(domain['name']))

        if not ve_exist:
            if 'win' in os_template.lower():
                ve_user = 'Administrator'
            else:
                ve_user = 'root'

            try:
                if domain and self.pva_client.set_ve_password(name=subscription_id, user=ve_user, password=ve_password):
                    LOG.info("Set VM {} password - ok".format(subscription_id))
                else:
                    LOG.error("Set VM {} password - failed".format(subscription_id))
                    raise FailRequest("Failed to set VM {} password".format(subscription_id))
            except Exception as error:
                LOG.error(traceback.format_exc())
                raise FailRequest(str(error))
        return domain

    def test_marketplace_requests_filter(self, conf, request_id, marketplace):
        if conf.misc['testMarketplaceId']:
            if conf.misc['testMode'] and marketplace.id != conf.misc['testMarketplaceId']:
                LOG.warning('Skipping request %s because test mode is enabled '
                            'and request came not from test marketplace', request_id)
                return True
            if not conf.misc['testMode'] and marketplace.id == conf.misc['testMarketplaceId']:
                LOG.warning('Skipping request %s because test mode is disabled '
                            'and request came from test marketplace', request_id)
                return True
        return False

    @staticmethod
    def get_item_limit(item):
        try:
            limit_param = next((p for p in item.params if p.id == 'item_limit'), None)
            return int(limit_param.value)
        except Exception:
            return -1

    def get_quota(self, item, error=FailRequest("ERROR: REQUESTED LIMITS ARE HIGHER THEN HARD LIMITS")):
        if item is None:
            return 0
        quantity = item.quantity
        item_limit = self.get_item_limit(item)
        if item_limit >= 0:
            if quantity > item_limit:
                raise error
        if quantity < 0:
            quantity = 0
        return quantity

    @staticmethod
    def pwgen(length=24):
        """Generates pseudo-random password"""

        # letters not found in python3
        _PWCHARS = string.ascii_letters + string.digits

        return ''.join(random.sample(_PWCHARS, length))

    def process_fulfillment_request(self, request):
        conf = Config.get_instance()
        params = {p.id: p for p in request.asset.params}
        if "pp_password" in params:
            return self.process_pp_order(request, params)
        else:
            return self.process_pva_order(request, params, conf)

    def process_pp_order(self, request, params):
        # Params for Power Panel product order
        param_pp_url = params.get('pp_url')
        param_pp_user = params.get('pp_user')
        param_pp_password = params.get('pp_password')

        subscription_id = request.asset.id
        pp_url = self.pp_client.base_url(self.pp_client.pp_url)
        pp_user = request.asset.tiers.customer.id

        if request.type in ('purchase', 'resume', 'change'):
            # update params
            params_update = []

            try:
                # Create user or update password for power panel
                if self.create_or_update_pp_user(pp_user, param_pp_password.value):
                    LOG.info("[Power Panel order] User {} created".format(pp_user))
                    self.pp_client.resume_user(pp_user)
                else:
                    raise FailRequest('Failed to create user {}'.format(pp_user))

                param_pp_url.value = pp_url
                params_update.append(param_pp_url)
                param_pp_user.value = pp_user
                params_update.append(param_pp_user)
                params_update.append(param_pp_password)

            except SkipRequest:
                raise
            except Exception as error:
                LOG.error(traceback.format_exc())
                raise FailRequest(str(error))

            rv = self.get_answer(request.asset.product.id, 'grant')
            return rv, params_update
        elif request.type == 'suspend':
            if not self.pp_client.suspend_user(pp_user):
                raise FailRequest('Failed to suspend user {}'.format(pp_user))

            return self.get_answer(request.asset.product.id, 'revoke') or '', None

        elif request.type == 'cancel':
            if not self.pp_client.suspend_user(pp_user):
                raise FailRequest('Failed to suspend user {}'.format(pp_user))

            return self.get_answer(request.asset.product.id, 'revoke') or '', None

        LOG.warning("Do not know what to do with such request")
        raise SkipRequest()

    def process_pva_order(self, request, params, conf):
        param_domain_name = params.get('domain_name')
        param_domain_hostname = params.get('domain_hostname')
        param_domain_id = params.get('domain_id')
        param_domain_ips = params.get('domain_ips')
        param_ve_password = params.get('ve_password')
        param_os_template = params.get('os_template')
        param_resume_date = params.get('resume_date')
        param_migration_uuid = params.get('migration_uuid')

        subscription_id = request.asset.id
        pp_user = request.asset.tiers.customer.id

        if request.type in ('purchase', 'resume', 'change'):
            # update params
            params_update = []

            items = {item.mpn.lower(): item for item in request.asset.items}
            try:
                # Create user or update password for power panel
                if self.create_or_update_pp_user(pp_user):
                    LOG.info("[VM Creation order] User {} created".format(pp_user))
                else:
                    raise FailRequest('Failed to create or update user {}'.format(pp_user))

                ve_hostname = param_domain_hostname.value
                ve_password = param_ve_password.value
                os_template = param_os_template.value
                if request.type == 'purchase' and param_migration_uuid and param_migration_uuid.value:
                    domain = self.sync_migration_domain(
                        pp_user=pp_user,
                        subscription_id=subscription_id,
                        items=items,
                        ve_uuid=param_migration_uuid.value
                    )
                else:
                    domain = self.create_or_update_domain(
                        pp_user=pp_user,
                        subscription_id=subscription_id,
                        ve_hostname=ve_hostname,
                        os_template=os_template,
                        ve_password=ve_password,
                        items=items
                    )
                param_domain_name.value = domain['name']
                params_update.append(param_domain_name)
                param_domain_id.value = domain['id']
                params_update.append(param_domain_id)
                param_domain_ips.value = domain['ips']
                params_update.append(param_domain_ips)
                params_update.append(param_domain_hostname)
                if request.type == 'resume':
                    param_resume_date.value = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                    params_update.append(param_resume_date)

            except (FailRequest, AutomatorResponseError, PowerPanelResponseError) as error:
                if request.type == 'purchase' and conf.misc['domainDeleteOnFail'] and not param_migration_uuid:
                    try:
                        self.pva_client.delete_ve(subscription_id)
                    except Exception as err:
                        LOG.warning("Unable to delete VM, VA agent return error:\n{}".format(str(err)))
                self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                               operation_result='fail')
                raise FailRequest(str(error))
            except SkipRequest:
                raise
            except Exception as error:
                self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                               operation_result='fail')
                LOG.error(traceback.format_exc())
                raise FailRequest(str(error))

            self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                           operation_result='success')
            return self.get_answer(request.asset.product.id, 'grant'), params_update
        elif request.type == 'suspend':
            vm_name = param_domain_name.value
            vm_uuid = param_domain_id.value
            if not self.pva_client.stop_ve(vm_name):
                self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                               operation_result='fail')
                raise FailRequest('Failed to stop VM with UUID:[{}] and NAME:[{}]'.format(vm_uuid, vm_name))
            try:
                self.pp_client.unassign_ve(vm_uuid)
            except Exception:
                self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                               operation_result='fail')
                LOG.error(traceback.format_exc())
                raise FailRequest('Failed to detach vm {} from user user {}'.format(vm_name, pp_user))

            self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                           operation_result='success')
            return self.get_answer(request.asset.product.id, 'revoke') or '', None

        elif request.type == 'cancel':
            vm_name = param_domain_name.value
            vm_uuid = param_domain_id.value

            if conf.data_retention_period == 0:
                try:
                    self.pp_client.delete_instance_backups(vm_name)
                    self.pva_client.delete_ve_backups(vm_name)
                    LOG.info("Delete VE {} backups...ok".format(vm_name))
                except Exception as err:
                    LOG.warning("Delete backups for VE {} failed with error:\n{}".format(vm_name, err))

                try:
                    if not self.pva_client.delete_ve(vm_name):
                        self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                                       operation_result='fail')
                        raise FailRequest('Failed to delete VM with UUID:[{}] and NAME:[{}]'.format(vm_uuid, vm_name))
                except AutomatorNotFoundError:
                    LOG.warning(
                        "Looks like VM with UUID:[{}] and NAME:[{}] already deleted, skipping...".format(vm_uuid,
                                                                                                         vm_name))
                LOG.info("VM with UUID:[{}] and NAME:[{}] deleted".format(vm_uuid, vm_name))
            else:
                try:
                    self.pva_client.stop_ve(vm_name)
                except AutomatorNotFoundError:
                    LOG.warning(
                        "Looks like VM with UUID:[{}] and NAME:[{}] already deleted, skipping...".format(vm_uuid,
                                                                                                         vm_name))
                try:
                    self.pp_client.unassign_ve(vm_uuid)
                except Exception:
                    self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                                   operation_result='fail')
                    LOG.error(traceback.format_exc())
                    raise FailRequest('Failed to detach vm {} from user user {}'.format(vm_name, pp_user))

            self.post_hook(conf=conf, subscription_id=subscription_id, request_type=request.type,
                           operation_result='success')
            return self.get_answer(request.asset.product.id, 'revoke') or '', None

        LOG.warning("Do not know what to do with such request")
        raise SkipRequest()

    def create_usage_file(self, report_name, report_description, request, start_report_time, end_report_time):
        usage_file = UsageFile(
            name=report_name,
            product=Product(id=request.product.id),
            contract=Contract(id=request.contract.id),
            description=report_description,
        )
        return usage_file

    def is_resource_exist(self, subscription_id):
        return self.pva_client.ve_exist(subscription_id)

    def is_backend_alive(self):
        try:
            self.pva_client.get_ip_pools_list()  # check pva mn api
            self.pp_client.get_userid_by_name('admin')  # check power panel api
        except Exception as err:
            LOG.error("Backend not working, self test finished with error:\n{}".format(err))
            LOG.error(traceback.format_exc())
            return False
        return True

    @staticmethod
    def is_report_suspended_needed():
        c = Config.get_instance()
        return c.report_suspended

    def delete_canceled_sub_backups(self):
        c = Config.get_instance()

        if self.pva_client.refresh_ve_backups():
            LOG.info("Backup refresh job successfully initiated")
        else:
            LOG.error('Backup refresh job initiated failed, please check it manually via pva-mn')

        if c.data_retention_period == 0:
            LOG.info("Remove backups for terminated subscription job skipped, because data_retention_period is 0, "
                     "backups removed immediately during cancelation request")
            return
        filters = Query().equal('status', 'terminated')
        assets = list(Directory().list_assets(filters=filters))

        for a in assets:
            subscription_id = a.id
            updated_at = a.events.updated.at
            days_after_modify = datetime.today() - updated_at
            if days_after_modify.days >= c.data_retention_period:
                LOG.info(
                    "PROCESS >>>> SUBSCRITPION: {} : Days after cancellation request:{}, Retention period: {}".format(
                        subscription_id, days_after_modify.days, c.data_retention_period))
                try:
                    self.pva_client.delete_ve_backups(subscription_id)
                    LOG.info("Remove backups for terminated subscription {}...done".format(subscription_id))
                except Exception as err:
                    LOG.warning(
                        "Remove backups for terminated subscription {}...failed\n{}".format(subscription_id, err))

    def delete_canceled_subscriptions(self):
        c = Config.get_instance()

        if c.data_retention_period == 0:
            LOG.info("Removal of terminated subscriptions job skipped, because data_retention_period is 0, "
                     "subscription removed immediately during cancellation request")
            return
        filters = Query().equal('status', 'terminated')
        assets = list(Directory().list_assets(filters=filters))

        for a in assets:
            subscription_id = a.id
            updated_at = a.events.updated.at
            days_after_modify = datetime.today() - updated_at
            if days_after_modify.days >= c.data_retention_period:
                LOG.info(
                    "PROCESS >>>> SUBSCRITPION: {} : Days after cancellation request:{}, Retention period: {}".format(
                        subscription_id, days_after_modify.days, c.data_retention_period))
                try:
                    self.pp_client.delete_instance_backups(subscription_id)
                    self.pva_client.delete_ve_backups(subscription_id)
                    LOG.info("Remove backups for terminated subscription {}...done".format(subscription_id))
                except Exception as err:
                    LOG.warning(
                        "Remove backups for terminated subscription {}...failed\n{}".format(subscription_id, err))

                try:
                    self.pva_client.delete_ve(subscription_id)
                    LOG.info("Remove terminated subscription {}...done\n".format(subscription_id))
                except AutomatorNotFoundError:
                    LOG.info("Subscription {} already removed...skipped\n".format(subscription_id))
                except Exception as err:
                    LOG.warning("Remove terminated subscription {}...failed\n{}".format(subscription_id, err))

    def sync_subscriptions(self):

        filters = Query().in_('status', ['active', 'suspended'])
        assets = list(Directory().list_assets(filters=filters))
        instances = {ve['uuid']: ve for ve in self.pp_client.get_instances()}
        for a in assets:
            subscription_id = a.id
            customer_id = a.tiers.customer.id
            params = {param.id: param for param in a.params}
            ve_name = None
            ve_state = None
            ve_cpu_count = None
            ve_ram = None
            ve_disk_size = None
            ve_extra_ip_count = None
            if 'domain_id' in params and params['domain_id']:
                uuid = params['domain_id'].value
                if uuid in instances:
                    ve_name = instances[uuid]['sdk_name']
                    ve_state = instances[uuid]['state']
                    ve_cpu_count = int(instances[uuid]['config']['cpu'])
                    ve_ram = int(instances[uuid]['config']['memory']) / 1024
                    ve_disk_size = int(instances[uuid]['config']['storage']) / 1024
                    ve_extra_ip_count = len(instances[uuid]['ips']) - 1
                    if ve_extra_ip_count < 0:
                        ve_extra_ip_count = 0
            elif 'pp_password' in params:
                LOG.info("[Subscription sync]: Power Panel subscription {}...skipped".format(
                    subscription_id))
            else:
                LOG.warning("[Subscription sync]: Can't process {}, ordering parameter domain_id is not set".format(
                    subscription_id))
                continue

            if not ve_name:
                LOG.warning("[Subscription sync]: Can't process sync for {}, env with uuid {} not found".format(
                    subscription_id, uuid))
                continue

            if ve_name == subscription_id:
                LOG.info("[Subscription sync]: Subscription {} already synced...skipped".format(subscription_id))
                continue

            LOG.info("[Subscription sync]: Starting sync of {}, change ve_name from {} to {}".format(
                subscription_id, ve_name, subscription_id))

            # Create user and assing VE to user
            try:
                if not self.pp_client.get_userid_by_name(customer_id) and self.create_or_update_pp_user(
                        pp_user=customer_id):
                    LOG.info("[Subscription sync]: Create user {}...ok".format(customer_id))

                if self.pp_client.assign_ve_to_user(instance_id=uuid, user_name=customer_id):
                    LOG.info("[Subscription sync]: Assign VE {} to user {}...ok".format(ve_name, customer_id))
                else:
                    LOG.error("[Subscription sync]: Assign VE {} to user {}...failed".format(ve_name, customer_id))
                    continue
            except Exception as err:
                LOG.error("[Subscription sync]: Sync of {} finished with error:\n{}".format(subscription_id, err))

            # Rename VE to subscription_id
            try:
                if ve_state == 'running' and self.pva_client.stop_ve(ve_name):
                    LOG.info("[Subscription sync]: Stop VE {}...ok".format(ve_name))
                elif ve_state == 'running':
                    LOG.error("[Subscription sync]: Stop VE {}...failed".format(ve_name))
                    continue
                if self.pva_client.update_ve(
                        name=ve_name,
                        ram=ve_ram,
                        cpu_cores=ve_cpu_count,
                        disk_size=ve_disk_size,
                        fip_count=ve_extra_ip_count,
                        new_name=subscription_id
                ):
                    LOG.info("[Subscription sync]: Update VE {}, changing name to {}...ok".format(
                        ve_name, subscription_id))
                else:
                    LOG.error("[Subscription sync]: Update VE {}, changing name to {}...failed".format(
                        ve_name, subscription_id))

                if ve_state == 'running' and self.pva_client.start_ve(subscription_id):
                    LOG.info("[Subscription sync]: Start VE {}...ok".format(ve_name))
                elif ve_state == 'running':
                    LOG.error("[Subscription sync]: Start VE {}...failed".format(ve_name))

            except Exception as err:
                LOG.error("[Subscription sync]: Sync of {} finished with error:\n{}".format(subscription_id, err))

    @staticmethod
    def post_hook(conf, subscription_id, request_type, operation_result):
        if conf.post_hook_script and os.path.exists(conf.post_hook_script):
            try:
                subprocess.call([conf.post_hook_script, subscription_id, request_type, operation_result],
                                timeout=conf.post_hook_exec_timeout)
                LOG.info('[POST_HOOK]: {} {} {} {}'.format(conf.post_hook_script, subscription_id, request_type,
                                                           operation_result))
            except subprocess.TimeoutExpired:
                LOG.warning('[POST_HOOK]: Parameters [{}, {}, {}, {}] script execution is too long, please increase '
                            'post_hook_exec_timeout(current value is {} seconds), or optimize your post hook '
                            'script'.format(conf.post_hook_script, subscription_id, request_type,
                                            operation_result, conf.post_hook_exec_timeout))
            except Exception as err:
                LOG.warning('[POST_HOOK]: finished with error:\n' + str(err))
        else:
            LOG.info('[POST_HOOK]: script does not exist...skipped')
