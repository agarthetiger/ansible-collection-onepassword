# https://github.com/ansible/ansible/blob/stable-2.9/lib/ansible/plugins/lookup/onepassword.py
# used as a starting point
# Copyright: (c) 2018, Scott Buchanan <sbuchanan@ri.pn>
# Copyright: (c) 2016, Andrew Zenk <azenk@umn.edu> (lastpass.py used as starting point)
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
name: onepassword
plugin_type: inventory
author:
- Andrew Garner <@agarthetiger>

short_description: 1Password dynamic inventory source

description:
- C(onepassword) wraps the C(op) command line utility to fetch hostnames/IPs from 1Password.
- Uses onepassword-inventory.(yml|yaml) YAML configuration file to set parameter values

requirements:
- C(op) 1Password command line utility. See U(https://support.1password.com/command-line/)

options:
    plugin:
        description: Token that ensures this is a source file for the 'onepassword' plugin.
        required: True
        choices: ['onepassword']
    vault:
        description: Vault containing the servers to retrieve (case-insensitive). If absent will search all vaults.
        required: False
        type: string
    master_password:
        description: The password used to unlock the specified vault. Only required when not already signed in via the C(op) CLI.
        required: False
        type: string
    subdomain:
        description: The 1Password subdomain to authenticate against. Only required when signing in for the first time and never signed in via the C(op) CLI.
        required: False
        type: string
    username:
        description: The username used to sign in. Only required when signing in for the first time and never signed in via the C(op) CLI.
        required: False
        type: string
    secret_key:
        description: The secret key used when performing an initial sign in. Only required when signing in for the first time and never signed in via the C(op) CLI.
        required: False
        type: string
notes:
- This script will use an existing 1Password session if one exists. If not, and you have already
  performed an initial sign in (meaning C(~/.op/config exists)), then only the C(master_password) is required.
  You may optionally specify C(subdomain) in this scenario, otherwise the last used subdomain will be used by C(op).
- This script can perform an initial login by providing C(subdomain), C(username), C(secret_key), and C(master_password).
- Due to the B(very) sensitive nature of these credentials, it is B(highly) recommended that you only pass in the minimal credentials
  needed at any given time. Ideally sign in to the op CLI before using this as an inventory source. 
- Suggest a specific automation user is created with access to only the vault containing the inventory required. Also, 
  store the user credentials in an Ansible Vault using a key that is equal to or greater in strength to the 1Password master password.
- Tested with C(op) version 1.0.0
'''

import errno
import json
import os

from subprocess import Popen, PIPE

from ansible.module_utils._text import to_bytes, to_text

from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.utils.display import Display
from ansible.errors import AnsibleError

display = Display()


class OnePass(object):

    def __init__(self, path='op'):
        self.cli_path = path
        self.config_file_path = os.path.expanduser('~/.op/config')
        self.logged_in = False
        self.token = None
        self.subdomain = None
        self.username = None
        self.secret_key = None
        self.master_password = None

    def get_token(self):
        if os.path.isfile(self.config_file_path):
            if not self.master_password:
                raise AnsibleError('Unable to sign in to 1Password. master_password is required.')
            try:
                args = ['signin', '--output=raw']
                if self.subdomain:
                    args = ['signin', self.subdomain, '--output=raw']

                rc, out, err = self._run(args, command_input=to_bytes(self.master_password))
                self.token = out.strip()
            except AnsibleError:
                self.full_login()
        else:
            self.full_login()

    def assert_logged_in(self):
        try:
            rc, out, err = self._run(['get', 'account'], ignore_errors=True)
            if rc == 0:
                self.logged_in = True
            if not self.logged_in:
                self.get_token()
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise AnsibleError("1Password CLI tool '%s' not installed in path on control machine" % self.cli_path)
            raise e

    def full_login(self):
        if None in [self.subdomain, self.username, self.secret_key, self.master_password]:
            raise AnsibleError('Unable to perform initial sign in to 1Password. '
                               'subdomain, username, secret_key, and master_password are required to perform initial sign in.')

        args = [
            'signin',
            '{0}.1password.com'.format(self.subdomain),
            to_bytes(self.username),
            to_bytes(self.secret_key),
            '--output=raw',
        ]

        rc, out, err = self._run(args, command_input=to_bytes(self.master_password))
        self.token = out.strip()

    def get_item(self, item_id, vault=None):
        args = ["get", "item", item_id]
        if vault:
            args += ['--vault={0}'.format(vault)]
        if not self.logged_in:
            args += [to_bytes('--session=') + self.token]
        rc, output, dummy = self._run(args)
        return output

    def list_items(self, vault=None):
        args = ["list", "items"]
        if vault:
            args += ['--vault={0}'.format(vault)]
        if not self.logged_in:
            args += [to_bytes('--session=') + self.token]
        rc, output, dummy = self._run(args)
        return output

    def list_servers(self, vault=None):
        items = json.loads(self.list_items(vault))
        servers = [item['uuid']
                   for item in items
                   if item['templateUuid'] == "110"]
        return servers

    def get_field(self, data_json, field_name, section_title=None):
        data = json.loads(data_json)
        if section_title is None:
            for field_data in data['details'].get('fields', []):
                if field_data.get('name', '').lower() == field_name.lower():
                    return field_data.get('value', '')
        for section_data in data['details'].get('sections', []):
            if section_title is not None and section_title.lower() != section_data['title'].lower():
                continue
            for field_data in section_data.get('fields', []):
                if field_data.get('t', '').lower() == field_name.lower():
                    return field_data.get('v', '')
        return ''

    def _run(self, args, expected_rc=0, command_input=None, ignore_errors=False):
        command = [self.cli_path] + args
        p = Popen(command, stdout=PIPE, stderr=PIPE, stdin=PIPE)
        out, err = p.communicate(input=command_input)
        rc = p.wait()
        if not ignore_errors and rc != expected_rc:
            raise AnsibleError(to_text(err))
        return rc, out, err


class InventoryModule(BaseInventoryPlugin):
    NAME = 'onepassword'
    OPTIONS = ('VAULT')

    def verify_file(self, path):
        """ return true/false if this is possibly a valid file for this plugin to consume """
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._read_config_data(path)

        op = OnePass()
        op.assert_logged_in()

        servers = op.list_servers(self.get_option('vault'))
        for server in servers:
            display.debug("uuid: " + str(server))
            server_details = op.get_item(server)
            hostname = op.get_field(server_details, 'hostname', 'network')
            display.debug("hostname: " + hostname)
            ip = op.get_field(server_details, 'ip', '')
            display.debug("ip: " + ip)
            group = op.get_field(server_details, 'group', '')
            display.debug("group: " + group)
            if ip:
                if group:
                    groups = self.inventory.get_groups_dict()
                    if group not in groups.keys():
                        self.inventory.add_group(group)
                self.inventory.add_host(ip, group=group if group else None)
                # self.inventory.set_variable(ip, 'ethernet_mac_address', server['Ethernet MAC'])
