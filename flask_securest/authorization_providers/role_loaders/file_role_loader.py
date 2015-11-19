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

from flask import current_app
import yaml

from flask.ext.securest.authorization_providers.role_loaders. \
    abstract_role_loader import AbstractRoleLoader
from flask_securest import rest_security


class FileRoleLoader(AbstractRoleLoader):

    def __init__(self, user_roles):
        self.user_roles = user_roles

    def get_roles(self):
        principals = rest_security.get_principals_list()
        with open(self.user_roles, 'r') as f:
            all_user_roles = yaml.safe_load(f.read())
        roles = set()
        for principal in principals:
            if principal in all_user_roles:
                user_roles = all_user_roles.get(principal).get('roles')
            for role in user_roles or []:
                roles.add(role)

        return roles
