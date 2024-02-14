# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
# -*- coding: utf-8 -*-

import sys
sys.path.append('../../cloudblue_connector')

import json
import requests
from keystoneauth1 import identity
from keystoneauth1.session import Session as KeystoneSession
from keystoneclient.v3.client import Client as KeystoneClient
from keystoneclient.exceptions import NotFound as KeystoneNotFound
from keystoneclient.exceptions import BadRequest as KeystoneBadRequest
from keystoneclient.exceptions import Conflict as KeystoneConflict
from urllib.parse import urlparse

from cloudblue_connector.core import getLogger

import urllib3
urllib3.disable_warnings()

LOG = getLogger("Connector")

class PowerPanelResponseError(Exception):
    """Raised when rest api response is not a valid json or response code was incorrect"""
    pass


class PowerPanel(object):
    def __init__(self, pp_url, keystone_endpoint, login, password, domain):
        self.pp_url = pp_url
        self.keystone_endpoint = keystone_endpoint
        self.login = login
        self.password = password
        self.domain = domain

    @staticmethod
    def base_url(url, with_path=False):
        parsed = urlparse(url)
        path = '/'.join(parsed.path.split('/')[:-1]) if with_path else ''
        parsed = parsed._replace(path=path)
        parsed = parsed._replace(params='')
        parsed = parsed._replace(query='')
        parsed = parsed._replace(fragment='')
        return parsed.geturl()

    @property
    def keystone_session(self):
        auth = identity.v3.Password(
            auth_url=self.keystone_endpoint,
            username=self.login,
            project_name=self.login,
            password=self.password,
            user_domain_name=self.domain,
            project_domain_name=self.domain,
            reauthenticate=True,
        )
        return KeystoneSession(auth=auth, verify=False)

    @property
    def keystone_client(self):
        return KeystoneClient(
            session=self.keystone_session,
            endpoint_override=self.keystone_endpoint,
            connect_retries=2,
        )

    @property
    def token(self):
        json_data = {'auth': {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "domain": {"id": self.domain},
                        "name": self.login,
                        "password": self.password
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {"id": self.domain},
                    "name": self.login
                }
            }
        }}
        headers = {"Content-Type": "application/json"}
        response = requests.post(self.pp_url + '/auth/tokens', data=json.dumps(json_data), headers=headers,
                                 verify=False)

        if response.ok and response.status_code == 201:
            return response.headers['X-Subject-Token']
        else:
            raise Exception("Can't get session, api call returned status code {}".format(response.status_code))

    def _send_request(self, end_point, rtype='get', payload=None, get_args=''):
        headers = {"Content-Type": "application/json", "X-Auth-Token": self.token}
        url = '{}/{}{}'.format(self.pp_url, end_point, get_args)

        send_request = requests.get
        if rtype == 'post':
            send_request = requests.post
        elif rtype == 'put':
            send_request = requests.put
        elif rtype == 'delete':
            send_request = requests.delete

        if payload:
            resp = send_request(url, data=json.dumps(payload), headers=headers, verify=False)
        else:
            resp = send_request(url, headers=headers, verify=False)

        LOG.info('\n Resp Code: {}\n Request url: {},\n Payload: {},\n Resp: Content: {}'.format(resp.status_code, url, payload, resp.text))

        return self._verified_resp(resp)


    @staticmethod
    def _verified_resp(response):
        if not response.ok:
            raise Exception("Api server internal error, http status code:{}".format(response.status_code))
        try:
            return response.json()
        except Exception:
            raise Exception("Api server response is not a valid json\n Response text:\n{}".format(response.text))

    def _add(self, end_point, payload):
        return self._send_request(end_point=end_point, payload=payload, rtype='post')

    def _update(self, end_point, payload):
        return self._send_request(end_point=end_point, payload=payload, rtype='put')

    def _get(self, end_point):
        return self._send_request(end_point=end_point, rtype='get')

    def _delete(self, end_point, payload=None):
        return self._send_request(end_point=end_point, rtype='delete', payload=payload)

    def get_instances(self):
        return self._get('/instances')

    def get_users(self):
        return self._get('/users')

    def get_projects(self):
        return self._get('/projects')

    def get_hosts(self):
        return self._get('/hosts')

    def is_host_exist(self, hostname):
        return any(h['hostname'] == hostname for h in self.get_hosts())

    def create_user(self, name, password=None,
                    description=None, enabled=True):
        user_id = self.get_userid_by_name(name)
        if user_id:
            LOG.exception('Create Power Panel user skipping, user {} exist.'.format(name))
            return self.keystone_client.users._get(user_id)
        else:
            try:
                return self.keystone_client.users.create(name=name, password=password, default_project=name,
                                                         description=description, enabled=enabled)
            except (KeystoneConflict, KeystoneBadRequest) as error:
                LOG.exception('Something wrong with the requested name or password')
                raise PowerPanelResponseError(error)

    def create_project(self, name, description=None, enabled=True):
        try:
            project_id = self.get_project_id_by_username(name)
            if project_id:
                LOG.exception('Create Power Panel project skipping, project {} exist.'.format(name))
                return self.keystone_client.projects._get(project_id)
        except KeystoneNotFound:
            pass

        try:
            return self.keystone_client.projects.create(
                name=name, description=description, domain=self.domain, enabled=enabled)
        except (KeystoneConflict, KeystoneBadRequest):
            LOG.exception('Something wrong with the requested name')

    def _operate_user(self, name, enabled=True, password=None):
        try:
            user_id = self.get_userid_by_name(name)
            if user_id and password:
                return self.keystone_client.users.update(user_id, enabled=enabled, password=password)
            elif user_id and not password:
                return self.keystone_client.users.update(user_id, enabled=enabled)
            else:
                LOG.error('User {} not found'.format(name))
        except (KeystoneConflict, KeystoneBadRequest) as error:
            LOG.exception('Something wrong with the requested name')
            raise PowerPanelResponseError(error)
        return True

    def update_user_password(self, name, password):
        return self._operate_user(name, password=password)

    def suspend_user(self, name):
        return self._operate_user(name, enabled=False)

    def resume_user(self, name):
        return self._operate_user(name, enabled=True)

    def assign_user_role(self, user, project):
        role = self.keystone_client.roles.find(name='member').id
        return self.keystone_client.roles.grant(role, user=user, project=project)

    def get_username_by_id(self, user_id):
        users = {u['id']: u for u in self.get_users()['users']}
        if user_id in users:
            return users[user_id]['name']
        else:
            raise KeystoneNotFound("User with provided id: {} does not exist".format(user_id))

    def get_userid_by_name(self, user_name):
        users = {u['name']: u for u in self.get_users()['users']}
        if user_name in users:
            return users[user_name]['id']
        return None

    def get_user_domain_count(self, user_name):
        user_id = self.get_userid_by_name(user_name)
        domains_count = 0
        if not user_id:
            return domains_count
        for domain in self.get_instances():
            if domain['user_id'] == user_id:
                domains_count += 1
        return domains_count

    def get_project_id_by_username(self, user_name):
        projects = {p['name']: p for p in self.get_projects()['projects']}
        if user_name in projects:
            return projects[user_name]['id']
        else:
            raise KeystoneNotFound("There are no projects belong to user: {}".format(user_name))

    def assign_ve_to_user(self, instance_id, user_name):
        project_id = self.get_project_id_by_username(user_name)
        user_id = self.get_userid_by_name(user_name)
        if not user_id:
            raise PowerPanelResponseError("User {} not found".format(user_name))

        payload = {"project_id": project_id, "user_id": user_id}
        return self._update(end_point='/instances/{}'.format(instance_id), payload=payload)

    def unassign_ve(self, instance_id):
        payload = {"project_id": "", "user_id": ""}
        return self._update(end_point='/instances/{}'.format(instance_id), payload=payload)

    def get_instance_by_name(self, name):
        instances = {ve['sdk_name']: ve for ve in self.get_instances()}
        if name in instances:
            return instances[name]
        return None

    def get_instance_params(self, name):
        instance = self.get_instance_by_name(name)
        print(instance)
        if instance:
            ve = {'type': instance['type'], 'state': instance['state'], 'ip_count': len(instance['ips']),
                  'storage': instance['config']['storage'], 'ram': instance['config']['memory'],
                  'cpu': instance['config']['cpu'], 'os': instance['config']['os-name']}
            return ve
        return None

    def get_instance_backups(self, name):
        instance = self.get_instance_by_name(name)
        if instance and 'uuid' in instance:
            uuid = instance['uuid']
            return self._get('/instances/{}/backups'.format(uuid))
        return None

    def get_instance_backups_size(self, name):
        backup_size = 0
        backups = self.get_instance_backups(name)
        if backups:
            for backup in backups:
                backup_size += backup['size']
        return {'backup_size': backup_size}

    def delete_instance_backups(self, name):
        backups = self.get_instance_backups(name)
        if backups:
            for backup in backups:
                success = self._delete('/instances/{}/backups/{}'.format(backup['instance_uuid'], backup['backup_id']))
                if success:
                    LOG.info("[Backup remove]: VE {} Backup_ID {}...done".format(name, backup['backup_id']))
                else:
                    LOG.error("[Backup remove]: VE {} Backup_ID {}...failed".format(name, backup['backup_id']))
        else:
            LOG.info("[Backup remove]: VE {}, there are no backups found...skipped".format(name))
