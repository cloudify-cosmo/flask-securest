#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from flask.ext.securest.userstores.abstract_userstore import AbstractUserstore


class SimpleUserstore(AbstractUserstore):

    def __init__(self, userstore):
        self.users = userstore['users']
        self.groups = userstore['groups']

    def get_user(self, username):
        if not username:
            raise ValueError('username is missing or empty')

        return self.find_user(username) or {}

    def get_all_principals_for_user(self, user_identifier):
        principals = []
        user_entry = self.find_user(user_identifier)
        if user_entry:
            principals.append(user_identifier)
            groups = user_entry.get('groups')
            if groups:
                for group in user_entry.get('groups'):
                    principals.append(group)

        return principals

    def get_roles(self, principal_name):
        all_roles = set()
        principal_entry = self.find_principal(principal_name)
        if principal_entry:
            for role in principal_entry.get('roles', []):
                all_roles.add(role)
        return all_roles

    def find_user(self, username):
        matching_entry = None
        for user_entry in self.users:
            if user_entry['username'] == username:
                matching_entry = user_entry
                break
        return matching_entry

    def find_group(self, group_name):
        matching_entry = None
        for group_entry in self.groups:
            if group_entry['name'] == group_name:
                matching_entry = group_entry
                break
        return matching_entry

    def find_principal(self, principal_name):
        matching_entry = self.find_user(principal_name)
        if matching_entry is None:
            matching_entry = self.find_group(principal_name)
        return matching_entry
