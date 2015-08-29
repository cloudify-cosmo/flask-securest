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

import re
import yaml

from flask_securest import rest_security
from flask_securest.authorization_providers.abstract_authorization_provider\
    import AbstractAuthorizationProvider


ALL_METHODS = '*'


class RoleBasedAuthorizationProvider(AbstractAuthorizationProvider):

    def __init__(self, role_loader, roles_config_file_path):
        self.role_loader = role_loader
        self.permissions_by_roles = \
            _load_permissions_from_file(roles_config_file_path)

    def authorize(self):
        target_endpoint = rest_security.get_endpoint()
        target_method = rest_security.get_http_method()
        user_roles = self.role_loader.get_roles()
        return self._is_authorized(target_endpoint, target_method, user_roles)

    def _is_authorized(self, target_endpoint, target_method, user_roles):
        for role in user_roles:
            permissions = self.permissions_by_roles.get(role, [])
            for endpoint, methods in permissions.iteritems():
                if _is_endpoint_permitted(target_endpoint=target_endpoint,
                                          permitted_endpoint=endpoint):
                    if _is_method_permitted(target_method=target_method,
                                            permitted_methods=methods):
                        # authorized!
                        return True
        return False


def _load_permissions_from_file(permissions_file_path):
    found_roles_permissions = {}
    with open(permissions_file_path, 'r') as config_file:
        yaml_conf = yaml.safe_load(config_file.read())

    for role, permissions in yaml_conf.iteritems():
        known_permissions = found_roles_permissions.get(role, {})
        for permission in permissions:
            known_permissions.update(permission)
        found_roles_permissions[role] = known_permissions
    return found_roles_permissions


def _is_method_permitted(target_method, permitted_methods):
    if permitted_methods == [ALL_METHODS]:
        return True
    allowed_methods = [value.upper() for value in permitted_methods]
    return target_method.upper() in allowed_methods


def _is_endpoint_permitted(target_endpoint, permitted_endpoint):
    if permitted_endpoint.startswith('/'):
        permitted_endpoint = permitted_endpoint[1:]
    if permitted_endpoint.endswith('/'):
        permitted_endpoint = permitted_endpoint[:-1]
    pattern = permitted_endpoint.replace('/', '\/').replace('*', '.*') + '$'
    if re.match(pattern, target_endpoint):
        return True
    else:
        # this is so that permission to "v2/blueprints/*" would approve
        # requests to access "v2/blueprints"
        if permitted_endpoint.endswith('/*'):
            return _is_endpoint_permitted(target_endpoint,
                                          permitted_endpoint[:-2])
        return False
