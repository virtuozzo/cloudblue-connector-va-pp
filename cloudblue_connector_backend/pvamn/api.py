# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-
import sys

sys.path.append('../../cloudblue_connector')

import re
from bs4 import BeautifulSoup
import xml.etree.ElementTree as elementTree
import base64
import socket
import time
from cloudblue_connector.core import getLogger
from .packet_builder import VMControlPacket, CTControlPacket, LocalSamplePacket, SharedSamplePacket, Pager2Packet, \
    ResUsagePacket, AuthPacket, IpPoolmPacket, ControlPacket, Backupm, BackupSubscriber

LOG = getLogger("Connector")


class AutomatorResponseError(Exception):
    """Raised when xml api response include error section"""
    pass


class AutomatorNotFoundError(Exception):
    """Raised when xml api response include error section"""
    pass


class AutomatorClient(object):
    def __init__(self, unix_socket=None, address=None, port=None, login=None, password=None, socket_read_delay=2,
                 socket_connection_timeout=600):
        self.unix_socket = unix_socket
        self.address = address
        self.port = port
        self.login = login
        self.password = password
        self.MSG_TERMINATOR = b'\0'
        self.SOCKET_READ_DELAY = socket_read_delay
        self.SOCKET_BUFFER_SIZE = 4096
        self.SOCKET_CONNECTION_TIMEOUT = socket_connection_timeout

    @staticmethod
    def encode_base64(string):
        string_bytes = string.encode("ascii")
        base64_bytes = base64.b64encode(string_bytes)
        base64_message = base64_bytes.decode('ascii')

        return base64_message

    @staticmethod
    def decode_base64(string):
        base64_bytes = string.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')

        return message

    @staticmethod
    def is_xml_valid(xml):
        try:
            elementTree.fromstring(xml)
        except elementTree.ParseError:
            return False
        return True

    def recv_all(self, session):
        data = b''
        LOG.debug("Waiting first part of response from socket...")
        retry = 1
        while True:
            part = session.recv(self.SOCKET_BUFFER_SIZE).strip(self.MSG_TERMINATOR)
            LOG.debug("Read data from socket in progress...")
            data += part
            if len(part) < self.SOCKET_BUFFER_SIZE:
                if not self.is_xml_valid(data) and retry < 5:
                    retry += 1
                    time.sleep(self.SOCKET_READ_DELAY)
                    continue
                LOG.debug("Read data from socket in done")
                break
        return data

    def send_request(self, packet_data, check_error=True):
        session = self.session
        LOG.debug("Send XML request to PVA MN:\n {}".format(packet_data))
        packet_data = packet_data.encode('utf-8') + self.MSG_TERMINATOR
        session.sendall(packet_data)
        resp = BeautifulSoup(self.recv_all(session), "xml")
        LOG.debug("Receive XML response from PVA MN:\n {}".format(resp))
        if check_error:
            self.check_response_error(resp)
        return resp

    @staticmethod
    def check_response_error(response):
        if response.find("error"):
            code = response.find('code').string
            message = response.find('message').string
            LOG.error('Error:{} Code:{}'.format(message, code))
            raise AutomatorResponseError('Error:{} Code:{}'.format(message, code))
        elif response.find('ok'):
            return True
        return False

    @property
    def session(self):
        if self.unix_socket:
            LOG.debug("Use UNIX Socket for PVA-MN")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.unix_socket)
            resp = BeautifulSoup(self.recv_all(sock), "xml")
            LOG.debug('Welcome XML:\n{}'.format(resp))
            self.check_response_error(resp)
            return sock

        LOG.debug("Use TCP Connection for PVA-MN")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.address, self.port))
        sock.settimeout(self.SOCKET_CONNECTION_TIMEOUT)
        resp = BeautifulSoup(self.recv_all(sock), "xml")
        self.check_response_error(resp)

        builder = AuthPacket()
        packet_data = builder.build_login(
            login=self.encode_base64(self.login),
            password=self.encode_base64(self.password)
        )
        LOG.debug("Auth login packet:\n{}".format(packet_data))
        packet_data = packet_data.encode('utf-8') + self.MSG_TERMINATOR
        sock.sendall(packet_data)
        resp = BeautifulSoup(self.recv_all(sock), "xml")
        self.check_response_error(resp)

        packet_data = builder.build_session(
            login=self.encode_base64(self.login),
            password=self.encode_base64(self.password)
        )
        packet_data = packet_data.encode('utf-8') + self.MSG_TERMINATOR
        LOG.debug("Auth session packet:\n{}".format(packet_data))
        sock.sendall(packet_data)
        resp = BeautifulSoup(self.recv_all(sock), "xml")
        self.check_response_error(resp)

        return sock

    def get_nodes_stat(self):
        params = ['cpu', 'disk', 'disk_usage', 'eid', 'hostname', 'memory', 'memory_usage', 'state',
                  'total_envs']
        nodes_stat = []
        packet_data = Pager2Packet().build_nodes_stat()
        resp = self.send_request(packet_data)

        for row in resp.find_all("row"):
            node = {}
            for index, encoded_prop in enumerate(row.text.split()):
                node[params[index]] = self.decode_base64(str(encoded_prop))
            nodes_stat.append(node)
        LOG.debug("get_nodes_stat => out:\n{}".format(nodes_stat))
        return nodes_stat

    def _get_node_from_pool(self):
        eid = None
        hostname = None
        ram_usage = 100.0
        ram_deny_limit = 90.0
        pools = self.get_ip_pools_list()
        bindings = []
        for pool in pools:
            for b in pool['bindings']:
                if b not in bindings:
                    bindings.append(b)

        if len(bindings) == 0:
            LOG.error("_get_node_from_pool There are no any assigned hardnode to IpPools")
            return eid

        for node in self.get_nodes_stat():
            if 'state' in node and node['state'] == "6" and float(node['memory']) < ram_usage and float(
                    node['memory']) < ram_deny_limit and node['eid'] in bindings:
                eid = node['eid']
                hostname = node['hostname']
                ram_usage = float(node['memory'])
        LOG.info("_get_node_from_pool choose node {}[{}]".format(hostname, eid))
        return eid

    def _is_node_online(self, eid):
        for node in self.get_nodes_stat():
            if 'state' in node and node['state'] == "6" and node['eid'] == eid:
                LOG.info("_is_node_online => Node: {}[{}], answer: YES".format(node['hostname'], eid))
                return True
            elif 'state' not in node and node['eid'] == eid:
                LOG.error("_is_node_online => Node: {}[{}], answer: NO".format(node['hostname'], eid))
                return False
        LOG.warning("_is_node_online => Node with uuid {} not found".format(eid))
        return False

    def _get_node_hostname(self, eid):
        for node in self.get_nodes_stat():
            if node['eid'] == eid and 'hostname' in node:
                return node['hostname']
        return 'Undefined'

    def get_ve_list(self, name=None):
        params = ['eid', 'env_type_name', 'ip_text', 'name', 'parent_eid', 'parent_title', 'state']
        nodes_list = []

        builder = Pager2Packet()
        if name:
            packet_data = builder.build_ve_list(name.upper())
        else:
            packet_data = builder.build_ve_list()

        resp = self.send_request(packet_data)
        for row in resp.find_all("row"):
            node = {}
            prop_list = list(filter(None, row.text.split('\n')))

            # In current property list we have only one field with ip address which can be without value
            # In case if property list count not 7, we will push to prop list on 3rd element "Not set" value.
            if len(prop_list) == 6:
                prop_list.insert(2, 'bm90IHNldA==')

            for index, encoded_prop in enumerate(prop_list):
                node[params[index]] = self.decode_base64(str(encoded_prop))
            nodes_list.append(node)
        LOG.debug("get_ve_list => out:\n{}".format(nodes_list))
        return nodes_list

    def get_ve_info(self, name):
        for ve in self.get_ve_list(name):
            if ve['name'] == name:
                LOG.info("get_ve_info => VE {} info provided".format(name))
                LOG.debug("get_ve_info => out:\n{}".format(ve))
                return ve
        LOG.warning("get_ve_info => out: VE {} not found".format(name))
        return None

    def _get_ve_type(self, ve_type):
        if ve_type == 'virtuozzo':
            return 'ct'
        elif ve_type == 'parallels':
            return 'vm'
        return None

    def ve_exist(self, name):
        return any(ve['name'] == name for ve in self.get_ve_list(name))

    def update_network(self, net_dev, fip_count):
        if not net_dev:
            raise AutomatorNotFoundError("VE network device not found, can't process update request")

        builder = ControlPacket()

        net_addr = net_dev.find_all('ip_address')
        net_addr_count = len(net_addr)

        if net_addr_count == 0 and fip_count == 0:
            addr_packet = builder.build_attach_ip()
            addr_to_add = addr_packet.find('ip_address')
            net_dev.append(addr_to_add)
        elif net_addr_count == 0 and fip_count > 0:
            add_count = fip_count + 1
            for i in range(add_count):
                addr_packet = builder.build_attach_ip()
                addr_to_add = addr_packet.find('ip_address')
                net_dev.append(addr_to_add)
        elif net_addr_count - 1 < fip_count:
            add_count = fip_count - (net_addr_count - 1)
            for i in range(add_count):
                addr_packet = builder.build_attach_ip()
                addr_to_add = addr_packet.find('ip_address')
                net_dev.append(addr_to_add)
        elif net_addr_count - 1 > fip_count:
            remove_count = net_addr_count - 1 - fip_count
            for index, prop in enumerate(reversed(net_addr), start=1):
                prop.decompose()
                if index == remove_count:
                    break

        nameservers = net_dev.find_all('nameserver')
        ns_ips = []
        for ns in nameservers:
            ns_ip = ns.text
            if ns_ip in ns_ips:
                ns.decompose()
            else:
                ns_ips.append(ns_ip)

        return net_dev

    def create_ve(self, name, hostname, os_template, host_uuid=None):
        # Get Hypervisor from PVA-MN
        if not host_uuid:
            host_uuid = self._get_node_from_pool()

        if not host_uuid:
            LOG.error("Error: No free hardware")
            return False

        node_hostname = self._get_node_hostname(host_uuid)

        # Get template config:
        LOG.info('Try to found {} in hardnode local templates for VMs'.format(os_template))
        templates = self.get_templates(host_uuid)
        if os_template not in templates:
            LOG.info('Template {} in hardnode local templates for VMs not found.'.format(os_template))
            LOG.info('Try to found {} in hardnode local templates for CTs'.format(os_template))
            templates = self.get_templates(host_uuid, check_flavors=True)
            if os_template not in templates:
                LOG.info('Template {} in hardnode local templates for CTs not found.'.format(os_template))
                LOG.info('Try to found {} in shared templates storage for CTs and VMs'.format(os_template))
                templates = self.get_templates()
                if os_template not in templates:
                    err_message = "Can't find specified template {} on host node {}[{}] and shared templates storage for CTs and VMs.".format(
                        os_template, node_hostname, host_uuid)
                    LOG.error(err_message)
                    raise AutomatorNotFoundError(err_message)
                LOG.info('Found template {} in shared templates storage for CTs and VMs - ok.'.format(os_template))
            else:
                LOG.info('Found template {} in hardnode local templates for CTs - ok.'.format(os_template))
        else:
            LOG.info('Found template {} in hardnode local templates for VMs - ok.'.format(os_template))

        tpl_type = self._get_ve_type(templates[os_template].get('type'))
        tpl_virtual_config = templates[os_template].get('virtual_config')

        if tpl_type == 'vm':
            builder = VMControlPacket(host_uuid=host_uuid)
            packet_data = builder.build_create()
        elif tpl_type == 'ct':
            builder = CTControlPacket(host_uuid=host_uuid)
            packet_data = builder.build_create()
        else:
            err_message = "Current template type {} is not applicable for VMs or CTs".format(tpl_type)
            LOG.error(err_message)
            raise AutomatorResponseError(err_message)

        packet_data.find('create').append(tpl_virtual_config)
        config = packet_data.find('config')
        if tpl_type == 'vm':
            self.update_vm_config(config, name, hostname, os_template)
        else:
            self.update_ct_config(config, name, hostname)

        # check is node online before send request:
        if not self._is_node_online(host_uuid):
            raise AutomatorResponseError(
                "Something goes wrong, selected hardware node {}[{}] is not online".format(node_hostname, host_uuid))

        # Send request to PVA-MN
        LOG.info("Start VE {} creation process on HOST {}[{}]".format(name, node_hostname, host_uuid))
        self.send_request(packet_data)

        for i in range(30):
            if self.ve_exist(name):
                LOG.info('[Iteration:{}/30]: VE:{} appears'.format(i, name))
                break
            LOG.info('[Iteration:{}/30]: Waiting VE:{} appears in PVA-MN'.format(i, name))
            time.sleep(1)
            if i == 30:
                raise AutomatorNotFoundError('VE {} not found in PVA-MN'.format(name))

        # Get ve uuid and ips

        ve = self.get_ve_info(name)
        if ve:
            if tpl_type == 'ct':
                builder.ve_uuid = ve.get('eid')
                packet_data = builder.build_vnc_enable()
                self.send_request(packet_data)
            ve_info = {'id': ve.get('eid'), 'name': name, 'ips': ve.get('ip_text')}
            LOG.info("VE {} created with following data: {}".format(name, ve_info))
            return ve_info
        else:
            raise AutomatorNotFoundError('VE {} not found'.format(name))

    def update_ct_config(self, config, name, hostname, ram=None, cpu_cores=None, disk_size=None, fip_count=None,
                         cpu_limit_mhz=None):
        if name is not None:
            config.find_all('name')[-1].string = name
            host_name = BeautifulSoup('<hostname>{}</hostname>'.format(hostname), 'xml')
            config.append(host_name)
        else:
            config.find('on_boot').string = '1'

            for feature in config.find_all('features'):
                feature.decompose()

            ram_config = config.find(text=re.compile('physpages'))
            hdd_config = config.find(text=re.compile('diskspace'))
            hdd_dev = config.find('disk_list')
            cpu_cores_config = config.find(text=re.compile('cpus'))
            cpu_mhz_config = config.find(text=re.compile('cpulimit_mhz'))
            net_dev = config.find('net_device')

            ram_config.findNext('hard').string = ram
            ram_config.findNext('soft').string = ram

            hdd_config.findNext('hard').string = disk_size
            hdd_config.findNext('soft').string = disk_size
            hdd_dev.find('size').string = disk_size

            cpu_cores_config.findNext('hard').string = cpu_cores
            cpu_mhz_config.findNext('hard').string = cpu_limit_mhz

            self.update_network(net_dev, fip_count)

    def update_vm_config(self, config, name, hostname, os_template, ram=None, cpu_cores=None, disk_size=None,
                         fip_count=None, cpu_limit_mhz=None, resize=None):
        packet_start = '''<packet 
                                                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                                xmlns:ns3="http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes"
                                                xmlns:ns4="http://www.swsoft.com/webservices/vzl/4.0.0/types">
                                            '''
        packet_end = '</packet>'
        if name is not None:
            os_tag = config.find('os').find('name')
            if os_tag:
                os_tag.name = 'os_name'

            vm_name = config.find('name')
            if not vm_name:
                config.append(BeautifulSoup('<name>{}</name>'.format(name), 'xml'))
            else:
                vm_name.string = name

            if os_tag:
                config.find('os').find('os_name').name = 'name'
            config.append(BeautifulSoup('<hostname>{}</hostname>'.format(hostname), 'xml'))
            origin_sample = config.find('origin_sample')
            if origin_sample:
                origin_sample.string = os_template
            else:
                config.append(BeautifulSoup('<origin_sample>{}</origin_sample>'.format(os_template), 'xml'))

            hdd = config.find(
                lambda tag: tag.name == 'device' in tag.name and 'vm_hard_disk_device' in tag['xsi:type'])
            if not hdd:
                raise AutomatorNotFoundError("VM {} hard disk not found, can't process update request".format(name))

            # Looks like a bug with optical drive in case if iso image on shared storage
            # in template xml config do not included username and password for storage
            # so we receive shared storage inaccessible error during copy of this device.
            # For fix we will check emulation type of hard disk, if if have number 10, which mean
            # that is device from shared storage, we will copy login and password for future injection
            # in optical device in case if it have type 10 too.
            nfs_username_str, nfs_password_str, nfs_username_xml, nfs_password_xml = None, None, None, None
            for dev in config.find_all('device'):
                try:
                    dev.findNext('friendly_name').decompose()
                    emulation_type = dev.findNext('emulation_type').string
                    user_name_tmp = dev.findNext('user_name')
                    password_tmp = dev.findNext('password')
                    if emulation_type == '10' and not nfs_username_str and not nfs_password_str:
                        share_info = self.get_template_share_info()
                        self.encode_base64(str(share_info.get('user_name'))).rstrip()
                        nfs_username_str = self.encode_base64(str(share_info.get('user_name'))).rstrip()
                        nfs_password_str = self.encode_base64(str(share_info.get('password'))).rstrip()
                        nfs_username_xml = '<user_name>{}</user_name>'.format(nfs_username_str)
                        nfs_password_xml = '<password>{}</password>'.format(nfs_password_str)

                    if emulation_type == '10' and not user_name_tmp:
                        dev.append(BeautifulSoup(nfs_username_xml, 'xml'))
                    elif emulation_type == '10' and user_name_tmp:
                        user_name_tmp.string = nfs_username_str

                    if emulation_type == '10' and not password_tmp:
                        dev.append(BeautifulSoup(nfs_password_xml, 'xml'))
                    elif emulation_type == '10' and password_tmp:
                        password_tmp.string = nfs_password_str
                except:
                    pass
        else:
            # Set VM autostart
            # 0 - disabled
            # 1 - enabled
            # 2 - save previous state
            config.find('auto_start').string = '2'

            # Update cpu_cores ram cpu_limit_mhz
            config.find('cpu_count').string = cpu_cores
            config.find('memory_size').string = ram
            cpu_mhz = config.find('cpu_limit_mhz')
            if not cpu_mhz:
                cpu_mhz = packet_start + '<ns4:cpu_limit_mhz>{}</ns4:cpu_limit_mhz>'.format(cpu_limit_mhz) + packet_end
                cpu_mhz = BeautifulSoup(cpu_mhz, 'xml').find('cpu_limit_mhz')
                config.append(cpu_mhz)
            else:
                cpu_mhz.string = cpu_limit_mhz

            device_list = config.find('device_list')

            # Find hdd and update size
            hdd = device_list.find(
                lambda tag: tag.name == 'device' in tag.name and 'vm_hard_disk_device' in tag['xsi:type'])
            if not hdd:
                raise AutomatorNotFoundError("VM {} hard disk not found, can't process update request".format(name))
            hdd.find('summary_info').decompose()
            hdd.find('size').string = disk_size
            if resize:
                resize_fs = packet_start + '<ns3:resize_fs/>' + packet_end
                resize_fs = BeautifulSoup(resize_fs, 'xml').find('resize_fs')
                hdd.append(resize_fs)

            # update network device
            net_dev = device_list.find(lambda tag: tag.name == 'device' and 'vm_network_device' in tag['xsi:type'])
            self.update_network(net_dev, fip_count)

            # add updated devices list to vm config
            config.append(device_list)

    def disable_ct_startup(self, name):
        ve = self.get_ve_info(name)
        if ve:
            ve_uuid = ve.get('eid')
            host_uuid = ve.get('parent_eid')
        else:
            LOG.error('VE {} not found'.format(name))
            raise AutomatorNotFoundError('VE {} not found'.format(name))

        builder = CTControlPacket(
            ve_uuid=ve_uuid,
            host_uuid=host_uuid
        )
        packet_data = builder.build_ve_info()
        resp = self.send_request(packet_data)
        virtual_config = resp.find('virtual_config')
        del virtual_config['xsi:type']
        virtual_config.name = 'config'
        virtual_config = str(virtual_config)
        packet_start = '''<packet 
                                                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                                xmlns:ns3="http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes"
                                                xmlns:ns4="http://www.swsoft.com/webservices/vzl/4.0.0/types">
                                            '''
        packet_end = '</packet>'
        virtual_config = packet_start + virtual_config + packet_end
        config = BeautifulSoup(virtual_config, 'xml').find('config')
        config.find('on_boot').string = '0'
        packet_data = builder.build_update()
        packet_data.find('set').append(config)

        # check is node online before send request:
        if not self._is_node_online(host_uuid):
            raise AutomatorResponseError("Something goes wrong, selected hardware {} is not online".format(host_uuid))

        # Send update request
        node_hostname = self._get_node_hostname(host_uuid)
        if self.send_request(packet_data):
            LOG.info("VE {} startup disabled on host {}".format(name, node_hostname))
        else:
            LOG.error("VE {} startup disabling on host {} failed".format(name, node_hostname))

    def update_ve(self, name, ram, cpu_cores, disk_size, fip_count=0, cpu_limit_mhz=0, resize=False):
        ve = self.get_ve_info(name)
        if ve:
            ve_uuid = ve.get('eid')
            host_uuid = ve.get('parent_eid')
            ve_type = self._get_ve_type(ve.get('env_type_name'))
        else:
            err_message = 'VE {} not found'.format(name)
            LOG.error(err_message)
            raise AutomatorNotFoundError(err_message)

        LOG.info("Update VE {} with following values:\n"
                 "RAM: {}\n "
                 "CPU: {}\n "
                 "CPU_LIMIT: {}\n "
                 "DISK_SIZE: {}\n "
                 "FIP_COUNT: {}".format(str(name), str(ram), str(cpu_cores), str(cpu_limit_mhz), str(disk_size),
                                        str(fip_count)))

        if ve_type == 'ct':
            ram = str(ram * 1024 * 1024 / 4)  # convert GB to physpages, 1 physpages = 4k
            disk_size = str(disk_size * 1024 * 1024)
            builder = CTControlPacket(ve_uuid=ve_uuid, host_uuid=host_uuid)
        elif ve_type == 'vm':
            ram = str(ram * 1024)
            disk_size = str(disk_size * 1024)
            builder = VMControlPacket(ve_uuid=ve_uuid, host_uuid=host_uuid)
        else:
            raise AutomatorResponseError("Current VE type {} is unknown")

        cpu_cores = str(cpu_cores)
        cpu_limit_mhz = str(cpu_limit_mhz)

        packet_data = builder.build_ve_info()
        resp = self.send_request(packet_data)
        virtual_config = resp.find('virtual_config')
        del virtual_config['xsi:type']
        virtual_config.name = 'config'
        virtual_config = str(virtual_config)
        packet_start = '''<packet 
                                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                        xmlns:ns3="http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes"
                                        xmlns:ns4="http://www.swsoft.com/webservices/vzl/4.0.0/types">
                                    '''
        packet_end = '</packet>'
        virtual_config = packet_start + virtual_config + packet_end
        config = BeautifulSoup(virtual_config, 'xml').find('config')
        if ve_type == 'ct':
            self.update_ct_config(
                config,
                name=None,
                hostname=None,
                ram=ram,
                cpu_cores=cpu_cores,
                disk_size=disk_size,
                fip_count=fip_count,
                cpu_limit_mhz=cpu_limit_mhz
            )
        else:
            self.update_vm_config(
                config,
                name=None,
                hostname=None,
                os_template=None,
                ram=ram,
                cpu_cores=cpu_cores,
                disk_size=disk_size,
                fip_count=fip_count,
                cpu_limit_mhz=cpu_limit_mhz,
                resize=resize
            )

        # update vm config
        packet_data = builder.build_update()
        packet_data.find('set').append(config)

        node_hostname = self._get_node_hostname(host_uuid)
        # check is node online before send request:
        if not self._is_node_online(host_uuid):
            raise AutomatorResponseError(
                "Something goes wrong, selected hardware node {}[{}] is not online".format(node_hostname, host_uuid))

        # Send update request

        LOG.info("Start VM {} update process on HOST {}[{}]".format(name, node_hostname, host_uuid))
        self.send_request(packet_data)

        # Get VM ips after update
        time.sleep(2)
        ve = self.get_ve_info(name)
        if ve:
            ve_ips = ve.get('ip_text')
        else:
            raise AutomatorNotFoundError('VE {} not found'.format(name))
        return {'id': ve_uuid, 'name': name, 'ips': ve_ips}

    def operate_ve(self, name, action):
        ve = self.get_ve_info(name)
        if ve:
            eid = ve.get('eid')
            ve_type = self._get_ve_type(ve.get('env_type_name'))
            ve_state = ve.get('state')
            host_uuid = ve.get('parent_eid')
        else:
            raise AutomatorNotFoundError('VE {} not found'.format(name))

        if ve_state == "6" and action == 'start':
            LOG.info("VE {} already started, nothing to do".format(name))
            return True
        elif ve_state == "3" and action == 'stop':
            LOG.info("VE {} already stopped, nothing to do".format(name))
            return True
        elif ve_state == "5" and action == 'suspend':
            LOG.info("VE {} already suspended, nothing to do".format(name))
            return True

        # Prepare xml packet
        if ve_type == 'vm':
            builder = VMControlPacket(ve_uuid=eid, host_uuid=host_uuid)
        else:
            builder = CTControlPacket(ve_uuid=eid, host_uuid=host_uuid)

        packet_data = ''
        if action == 'start':
            packet_data = builder.build_start()
        elif action == 'stop':
            packet_data = builder.build_stop()
        elif action == 'suspend':
            packet_data = builder.build_suspend()
        elif action == 'delete':
            packet_data = builder.build_delete()

        # check is node online before send request:
        if not self._is_node_online(host_uuid):
            raise AutomatorResponseError("Something goes wrong, selected hardware {} is not online".format(host_uuid))

        # Send request
        resp = self.send_request(packet_data)
        if action == 'stop' and ve_type == 'ct':
            self.disable_ct_startup(name)

        if self.check_response_error(resp):
            LOG.info("{}_ve => VE {}...ok".format(action, name))
        else:
            LOG.error("{}_ve => VE {}...failed".format(action, name))
            return False

        return True

    def stop_ve(self, name):
        return self.operate_ve(name, 'stop')

    def start_ve(self, name):
        return self.operate_ve(name, 'start')

    def suspend_ve(self, name):
        return self.operate_ve(name, 'suspend')

    def delete_ve(self, name):
        if not self.stop_ve(name):
            return False
        return self.operate_ve(name, 'delete')

    def set_ve_password(self, name, user, password):
        ve = self.get_ve_info(name)
        if ve:
            eid = ve.get('eid')
            ve_type = self._get_ve_type(ve.get('env_type_name'))
            host_uuid = ve.get('parent_eid')
        else:
            raise AutomatorNotFoundError('VE {} not found'.format(name))

        # Prepare xml packet
        if ve_type == 'ct':
            builder = CTControlPacket(ve_uuid=eid, host_uuid=host_uuid)
        else:
            builder = VMControlPacket(ve_uuid=eid, host_uuid=host_uuid)
        packet_data = builder.build_set_password(user_name=user, user_password=self.encode_base64(str(password)))

        # check is node online before send request:
        if not self._is_node_online(host_uuid):
            raise AutomatorResponseError("Something goes wrong, selected hardware {} is not online".format(host_uuid))

        # Send request
        resp = None
        for i in range(50):
            resp = self.send_request(packet_data=packet_data, check_error=False)
            LOG.info("[Iteration:{}/50]: Waiting VM OS loading...".format(i))
            if resp.find('ok'):
                LOG.info("[Iteration:{}/50]: VM OS loaded...ok".format(i))
                break
            time.sleep(5)

        return self.check_response_error(resp)

    def get_network_usage(self, name, start_time, end_time):
        ve = self.get_ve_info(name)
        if ve:
            eid = ve.get('eid')
            host_uuid = ve.get('parent_eid')
            ve_type = self._get_ve_type(ve.get('env_type_name'))
        else:
            raise AutomatorNotFoundError('VE {} not found'.format(name))

        # calculate period current_date.strftime('%Y-%m-*')
        period = str(int(time.mktime(end_time.timetuple()) - time.mktime(start_time.timetuple())))
        start_time = start_time.strftime('%Y-%m-%dT%H:%M:%S+0000')
        end_time = end_time.strftime('%Y-%m-%dT%H:%M:%S+0000')

        # counters_vzp_net VM
        # counters_vz_net CT
        if ve_type == 'ct':
            class_name = 'counters_vz_net'
        else:
            class_name = 'counters_vzp_net'

        builder = ResUsagePacket(host_uuid)
        # Prepare xml packet
        packet_data = builder.build_net_usage(
            class_name=class_name,
            ve_uuid=eid,
            start_time=start_time,
            end_time=end_time,
            period=period
        )

        # Send request
        resp = self.send_request(packet_data)

        inc_bytes = 0
        out_bytes = 0
        for prop in resp.find_all('counter'):
            counter_name = prop.findNext('name').text
            if counter_name == 'counter_net_incoming_bytes':
                inc_bytes = prop.findNext('avg').text
            elif counter_name == 'counter_net_outgoing_bytes':
                out_bytes = prop.findNext('avg').text
                break

        return {'inc_bytes': inc_bytes, 'out_bytes': out_bytes}

    def get_templates(self, host_uuid=None, check_flavors=False):
        templates = []
        if host_uuid:
            builder = LocalSamplePacket(host_uuid=host_uuid)
            if check_flavors:
                packet_data = builder.build_ct_template()
                tag = 'sample'
            else:
                packet_data = builder.build_vm_template()
                tag = 'data'
            attrs = {}
        else:
            share_info = self.get_template_share_info()

            if 'status' in share_info and share_info['status'] == '0':
                LOG.info("Use {} as template share".format(share_info['file_share_path']))
            else:
                LOG.warning('Templates share {} is offline, skipping..'.format(share_info['file_share_path']))
                return templates
            packet_data = SharedSamplePacket().build_template()
            tag = 'ns2:sample'
            attrs = {"xsi:type": "ns2:env_sampleType"}

        resp = self.send_request(packet_data)
        tpl_rows = resp.find_all(tag, attrs=attrs)

        templates_list = []
        for row in tpl_rows:

            os_tag = row.findNext('os')
            if not os_tag:
                continue
            ve_type = row.findNext('type').text
            os_tag.find('name').name = 'os_name'
            tpl = BeautifulSoup(str(row), 'xml')

            node = {
                'id': row.findNext('id').text,
                'name': tpl.find_all('name')[-1].text,
                'type': ve_type
            }
            os_tag.find('os_name').name = 'name'
            # config
            packet_start = '<packet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance>"'
            packet_end = '</packet>'
            virtual_config = row.findNext('virtual_config')
            virtual_config.name = 'config'
            del virtual_config['xsi:type']

            if ve_type == 'parallels':
                virtual_config.find('is_template').decompose()

            virtual_config = str(virtual_config)
            virtual_config = re.sub(r' xsi:type="env_configType"', '', virtual_config)
            virtual_config = re.sub(r'ns[0-9]:', '', virtual_config)
            virtual_config = re.sub(r'(vm_(.*)_device)', r'ns1:\1', virtual_config)
            virtual_config = packet_start + virtual_config + packet_end
            node['virtual_config'] = BeautifulSoup(virtual_config, "xml").find('config')
            templates_list.append(node)
        templates = {t['name']: t for t in templates_list}
        LOG.debug("get_templates => out:\n {}".format(templates))
        return templates

    def get_template_share_info(self):
        params = ['file_share_path', 'flags', 'id', 'name', 'password', 'status', 'user_name']
        packet_data = Pager2Packet().build_tpl_share_info()
        resp = self.send_request(packet_data)

        share = {}
        for index, encoded_prop in enumerate(resp.find("row").text.split()):
            share[params[index]] = self.decode_base64(str(encoded_prop))
        LOG.debug("get_template_share_info => out:\n{}".format(share))
        return share

    def get_ip_pools_list(self):
        packet_data = IpPoolmPacket().build_pool_list()
        resp = self.send_request(packet_data)
        ip_pools = resp.find_all(lambda tag: tag.name == 'ip_pool' and 'ip_poolType' in tag['xsi:type'])

        pools_resp = []
        for pool in ip_pools:
            nameservers = []
            for ns in pool.findNext('nameservers').find_all('nameserver'):
                nameservers.append(ns.text)

            bindings_filter = pool.find_next('bindings')
            bindings = []
            if bindings_filter:
                for bind in bindings_filter.find_all('id'):
                    bindings.append(bind.text)
            gateway = pool.findNext('gateway')
            if gateway:
                gateway = gateway.string
            else:
                gateway = None

            p = {
                'id': pool.findNext('id').string,
                'name': pool.findNext('name').string,
                'start_ip': pool.findNext('start_ip').string,
                'end_ip': pool.findNext('end_ip').string,
                'gateway': gateway,
                'netmask': pool.findNext('netmask').string,
                'nameservers': nameservers,
                'bindings': bindings
            }
            pools_resp.append(p)
        return pools_resp

    def get_backups_list(self, name, search_removed=False):
        if search_removed:
            env_backup_info = self.get_env_backup_info(name)
            if 'env_id' not in env_backup_info:
                return []
            eid = env_backup_info['env_id']
        else:
            ve = self.get_ve_info(name)
            if ve:
                eid = ve.get('eid')
            else:
                raise AutomatorNotFoundError('VE {} not found'.format(name))

        params = ['container_eid', 'id', 'size', 'storage_title', 'time', 'type']
        builder = Pager2Packet()
        packet_data = builder.build_backup_list(eid)
        resp = self.send_request(packet_data)
        backups = []

        for row in resp.find_all("row"):
            backup = {}
            for index, encoded_prop in enumerate(row.text.split()):
                backup[params[index]] = self.decode_base64(str(encoded_prop))
            backups.append(backup)

        return backups

    def get_env_backup_info(self, name):
        params = ['env_id', 'env_title', 'node_title']
        builder = Pager2Packet()
        packet_data = builder.build_backup_list_grouped(name)
        resp = self.send_request(packet_data)

        backup_info = {}
        for row in resp.find_all("row"):
            for index, encoded_prop in enumerate(row.text.split()):
                backup_info[params[index]] = self.decode_base64(str(encoded_prop))

        return backup_info

    def get_ve_backup_size(self, name):
        backups_size = 0
        backups = self.get_backups_list(name)
        if len(backups) > 0:
            for backup in backups:
                backups_size = backups_size + int(backup.get('size'))

        # return bytes
        return {'backup_size': backups_size}

    def delete_ve_backups(self, name):
        backups = self.get_backups_list(name, search_removed=True)
        ve_backups_list = []
        if len(backups) > 0:
            for backup in backups:
                ve_backups_list.append(backup.get('id'))

        if len(ve_backups_list) == 0:
            return True
        builder = Backupm()
        packet_data = builder.build_delete_backups(ve_backups_list)
        resp = self.send_request(packet_data)
        return resp

    def refresh_ve_backups(self):
        builder = BackupSubscriber()
        packet_data = builder.build_refresh_backups()
        resp = self.send_request(packet_data)
        return self.check_response_error(resp)


