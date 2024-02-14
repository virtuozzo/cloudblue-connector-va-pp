# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET

from yattag import indent
from bs4 import BeautifulSoup


class Packet(object):
    target = None
    destination = None

    @property
    def root(self):
        root = ET.Element('packet')
        if self.target:
            tg = ET.SubElement(root, 'target')
            tg.text = self.target
        if self.destination:
            dst = ET.SubElement(root, 'dst')
            host = ET.SubElement(dst, 'host')
            host.text = self.destination
        return root

class AuthPacket(Packet):

    def build_login(self, login, password):
        self.target = None
        packet = self.root
        packet.set('xmlns:ns2', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set('version', '4.0.0')
        packet.set('id', '2')

        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, 'system')
        login_tag = ET.SubElement(va_target_module, 'login', attrib={"xsi:type": "ns2:auth_nameType"})
        name_tag = ET.SubElement(login_tag, 'ns2:name')
        name_tag.text = login
        realm = ET.SubElement(login_tag, 'ns2:realm')
        realm.text = '00000000-0000-0000-0000-000000000000'
        password_tag = ET.SubElement(login_tag, 'password')
        password_tag.text = password

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_session(self, login, password):
        self.target = 'sessionm'
        packet = self.root
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vzl/4.0.0/protocol')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        login_tag = ET.SubElement(va_target_module, 'login', attrib={"xsi:type": "ns1:auth_nameType"})
        name_tag = ET.SubElement(login_tag, 'ns1:name')
        name_tag.text = login
        realm = ET.SubElement(login_tag, 'ns1:realm')
        realm.text = '00000000-0000-0000-0000-000000000000'
        password_tag = ET.SubElement(login_tag, 'password')
        password_tag.text = password
        return BeautifulSoup(ET.tostring(packet), 'xml')

class ControlPacket(Packet):
    def __init__(self, ve_uuid=None, host_uuid=None):
        self.ve_uuid = ve_uuid
        self.destination = host_uuid

    @property
    def va_target_module(self):
        packet = self.root
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        return packet, va_target_module

    def _operate_ve(self, action):
        packet, va_target_module = self.va_target_module
        operation = ET.SubElement(va_target_module, action)
        if action == 'stop':
            ET.SubElement(operation, 'force')
        eid = ET.SubElement(operation, 'eid')
        eid.text = self.ve_uuid

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_start(self):
        return self._operate_ve('start')

    def build_stop(self):
        return self._operate_ve('stop')

    def build_suspend(self):
        return self._operate_ve('suspend')

    def build_delete(self):
        return self._operate_ve('destroy')

    def build_create(self):
        packet, va_target_module = self.va_target_module

        # Set namespaces
        packet.set("xmlns:ns1", "http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes")
        packet.set("xmlns:ns2", "http://www.swsoft.com/webservices/vzl/4.0.0/types")
        packet.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        packet.set("type", "2")
        packet.set("id", "s5gan5m3caaaaquc1azaykuvuiuscaaa/lkdlqcvbaaaaaquc1azqgsrehrxrcaaa")
        packet.set("version", "4.5.0")
        packet.set("log", "on")
        ET.SubElement(va_target_module, 'create')

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_ve_info(self):
        packet, va_target_module = self.va_target_module
        packet.set("id", "2")
        packet.set("version", "4.0.0")
        get_info = ET.SubElement(va_target_module, 'get_info')
        eid = ET.SubElement(get_info, 'eid')
        eid.text = self.ve_uuid
        ET.SubElement(get_info, 'config')

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_attach_ip(self):
        packet = ET.Element('packet')
        packet.set('xmlns:ns3', 'http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes')
        ip_addr = ET.SubElement(packet, 'ns3:ip_address')
        ip = ET.SubElement(ip_addr, 'ns3:ip')
        ip.text = '0.0.0.0'

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_set_password(self, user_name, user_password):
        packet, va_target_module = self.va_target_module
        set_user_password = ET.SubElement(va_target_module, 'set_user_password')
        eid = ET.SubElement(set_user_password, 'eid')
        eid.text = self.ve_uuid
        user = ET.SubElement(set_user_password, 'user')
        user.text = user_name
        password = ET.SubElement(set_user_password, 'password')
        password.text = user_password

        return BeautifulSoup(ET.tostring(packet), 'xml')



class VMControlPacket(ControlPacket):
    target = 'vzpenvm'

    def build_update(self):
        packet, va_target_module = self.va_target_module

        # Set namespaces
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vzl/4.0.0/protocol')
        packet.set('xmlns:ns2', 'http://www.swsoft.com/webservices/vzl/4.0.0/envm')
        packet.set('xmlns:ns3', 'http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes')
        packet.set('xmlns:ns4', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')

        # build config
        set = ET.SubElement(va_target_module, 'set')
        eid = ET.SubElement(set, 'eid')
        eid.text = self.ve_uuid
        set_mode = ET.SubElement(set, 'set_mode')
        set_mode.text = 'reboot'

        return BeautifulSoup(ET.tostring(packet), 'xml')



class CTControlPacket(ControlPacket):
    target = 'vzaenvm'

    def build_update(self):
        packet, va_target_module = self.va_target_module

        # Set namespaces
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vzl/4.0.0/protocol')
        packet.set('xmlns:ns2', 'http://www.swsoft.com/webservices/vzl/4.0.0/envm')
        packet.set('xmlns:ns3', 'http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes')
        packet.set('xmlns:ns4', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')

        # build config
        set = ET.SubElement(va_target_module, 'set')
        eid = ET.SubElement(set, 'eid')
        eid.text = self.ve_uuid

        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_vnc_enable(self):
        packet, va_target_module = self.va_target_module

        # Set namespaces
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vza/4.0.0/vzaenvm')
        packet.set('xmlns:ns2', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set("type", "2")
        packet.set("id", "s5gan5m3caaaaquc1azaykuvuiuscaaa/lkdlqcvbaaaaaquc1azqgsrehrxrcaaa")
        packet.set("version", "4.5.0")
        packet.set("log", "on")

        # build config
        set_vnc_server = ET.SubElement(va_target_module, 'set_vnc_server')
        eid = ET.SubElement(set_vnc_server, 'eid')
        mode = ET.SubElement(set_vnc_server, 'mode', attrib={"xsi:type": "ns1:vnc_auto"})
        ET.SubElement(mode, 'password')

        eid.text = self.ve_uuid

        return BeautifulSoup(ET.tostring(packet), 'xml')


class LocalSamplePacket(Packet):
    target = 'vzpsample_manager'

    def __init__(self, host_uuid):
        self.destination = host_uuid
    def build_template(self, vz_type=None):
        if vz_type == 'ct':
            self.target = 'vzasample_manager'

        packet = self.root

        # Set namespaces
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vzp/4.0.0/vzptypes')
        packet.set('xmlns:ns2', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set("type", "2")
        packet.set("id", "s5gan5m3caaaaquc1azaykuvuiuscaaa/lkdlqcvbaaaaaquc1azqgsrehrxrcaaa")
        packet.set("version", "4.5.0")
        packet.set("log", "on")

        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        ET.SubElement(va_target_module, 'get')
        return BeautifulSoup(ET.tostring(packet), 'xml')

    def build_vm_template(self):
        return self.build_template('vm')

    def build_ct_template(self):
        return self.build_template('ct')

class SharedSamplePacket(Packet):
    target = 'sample_manager'

    def build_template(self):
        packet = self.root
        packet.set('xmlns:ns1', 'http://www.swsoft.com/webservices/vzl/4.0.0/types')
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set('id', 'zyyze4jciaaaqkfigczatcpoc1xhaaaa')
        packet.set('type', '2')
        packet.set('priority', '0')
        packet.set('version', '4.5.0')
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        ET.SubElement(va_target_module, 'get')
        return BeautifulSoup(ET.tostring(packet), 'xml')


class Pager2Packet(Packet):
    target = 'pager2'

    def _build_pager2(self, list_value, fields, where=None):
        packet = self.root
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        select = ET.SubElement(va_target_module, 'select')
        list_tag = ET.SubElement(select, 'list')
        list_tag.text = list_value
        for field in fields:
            f = ET.SubElement(select, 'field')
            f.text = field

        xml = BeautifulSoup(ET.tostring(packet), 'xml')

        if where:
            filters = BeautifulSoup(ET.tostring(where), 'xml')
            xml.find('select').append(filters)
        return xml

    def build_tpl_share_info(self):
        fields = ['id', 'name', 'file_share_path', 'user_name', 'password', 'flags', 'status']
        return self._build_pager2('vFileShares', fields)

    def build_nodes_stat(self):
        fields = ['cpu', 'disk', 'disk_usage', 'eid', 'hostname', 'memory', 'memory_usage', 'state', 'total_envs']
        return self._build_pager2('vHosts', fields)

    def build_ve_list(self, ve_name=None):
        fields = ['eid', 'env_type_name', 'state', 'name', 'parent_title', 'parent_eid', 'ip_text']
        where = ET.Element('where')
        if ve_name:
            and_tag = ET.SubElement(where, 'and')
            like = ET.SubElement(and_tag, 'like')
            function = ET.SubElement(like, 'function')
            name = ET.SubElement(function, 'name')
            name.text = 'upper'
            field = ET.SubElement(function, 'field')
            field.text = 'title'
            value = ET.SubElement(like, 'value')
            value.text = ve_name
            escape_char = ET.SubElement(like, 'escape_char')
            escape_char.text = '/'
            ne = ET.SubElement(and_tag, 'ne')
        else:
            ne = ET.SubElement(where, 'ne')
        field = ET.SubElement(ne, 'field')
        field.text = 'parent_eid'
        value = ET.SubElement(ne, 'value')
        value.text = '00000000-0000-0000-0000-000000000000'

        return self._build_pager2('vEnvironments', fields, where)

    def build_backup_list(self, ve_uuid):
        fields = ['container_eid', 'time', 'storage_title', 'size', 'id', 'type']
        where = ET.Element('where')
        eq = ET.SubElement(where, 'eq')
        ET.SubElement(eq, 'field').text = 'container_eid'
        ET.SubElement(eq, 'value').text = ve_uuid
        return self._build_pager2('vBackupUnGrouped', fields, where)

    def build_backup_list_grouped(self, ve_name):
        fields = ['env_id', 'env_title', 'node_title']
        where = ET.Element('where')
        like = ET.SubElement(where, 'like')
        function = ET.SubElement(like, 'function')
        name = ET.SubElement(function, 'name')
        name.text = 'upper'
        field = ET.SubElement(function, 'field')
        field.text = 'env_title'
        value = ET.SubElement(like, 'value')
        value.text = ve_name
        escape_char = ET.SubElement(like, 'escape_char')
        escape_char.text = '/'
        return self._build_pager2('vBackupGrouped', fields, where)


class Backupm(Packet):
    target = 'backupm'

    def build_delete_backups(self, ve_uuid_list):
        packet = self.root
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set('id', '4ipkw1uhebaaata6q5ywc4e6x16icaaa')
        packet.set('type', '2')
        packet.set('version', '4.5.0')
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        for backup_id in ve_uuid_list:
            remove = ET.SubElement(va_target_module,'remove')
            ET.SubElement(remove, 'backup_id').text = backup_id
            ET.SubElement(remove, 'options')

        return BeautifulSoup(ET.tostring(packet), 'xml')

class BackupSubscriber(Packet):
    target = 'backup_subscriber'

    def build_refresh_backups(self):
        packet = self.root
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set('id', '4ipkw1uhebaaata6q5ywc4e6x16icaaa')
        packet.set('type', '2')
        packet.set('version', '4.5.0')
        packet.set('progress','off')
        packet.set('log', 'on')
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        ET.SubElement(va_target_module, 'reload_all')

        return BeautifulSoup(ET.tostring(packet), 'xml')

class ResUsagePacket(Packet):
    target = 'res_log'

    def __init__(self, host_uuid):
        self.destination = host_uuid

    def build_net_usage(self, class_name, ve_uuid, start_time, end_time, period):
        packet = self.root
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        get_log = ET.SubElement(va_target_module, 'get_log')
        eid = ET.SubElement(get_log, 'eid')
        eid.text = ve_uuid
        class_tag = ET.SubElement(get_log, 'class')
        class_name_tag = ET.SubElement(class_tag, 'name')
        class_name_tag.text = class_name
        start_time_tag = ET.SubElement(get_log, 'start_time')
        start_time_tag.text = start_time
        end_time_tag = ET.SubElement(get_log, 'end_time')
        end_time_tag.text = end_time
        period_tag = ET.SubElement(get_log, 'period')
        period_tag.text = period
        ET.SubElement(get_log, 'report_empty')

        return BeautifulSoup(ET.tostring(packet), 'xml')

class IpPoolmPacket(Packet):
    target = 'ip_poolm'

    def build_pool_list(self):
        packet = self.root
        packet.set('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        packet.set('id', 'w6y4v5niaaaaqj61uczw6j1myt2zaaaa')
        packet.set('type', '2')
        packet.set('version', '4.5.0')
        data = ET.SubElement(packet, 'data')
        va_target_module = ET.SubElement(data, self.target)
        ET.SubElement(va_target_module, 'list_ip_pool')
        return BeautifulSoup(ET.tostring(packet), 'xml')
