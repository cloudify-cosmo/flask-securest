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
import logging
import os

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from flask_securest import rest_security
from flask_securest.authorization_providers.abstract_authorization_provider\
    import AbstractAuthorizationProvider
from flask_securest.constants import FLASK_SECUREST_LOGGER_NAME


ANY = '*'


class RoleBasedAuthorizationProvider(AbstractAuthorizationProvider,
                                     FileSystemEventHandler):

    def __init__(self, role_loader, roles_config_file_path):
        self.lgr = logging.getLogger(FLASK_SECUREST_LOGGER_NAME)
        self.role_loader = role_loader
        self.permissions_by_roles = None
        self.roles_config_file_path = os.path.abspath(roles_config_file_path)
        self.observer = Observer()
        self.observer.schedule(self,
                               path=os.path.dirname(
                                   self.roles_config_file_path),
                               recursive=False)
        self.load_roles_config()
        self.observer.start()

    def load_roles_config(self):
        try:
            with open(self.roles_config_file_path, 'r') as config_file:
                self.permissions_by_roles = yaml.safe_load(config_file.read())
                self.lgr.info('Loading of roles configuration ended '
                              'successfully')
        except (yaml.parser.ParserError, IOError) as e:
            err = 'Failed parsing {role_config_file} file. Error: {error}.' \
                .format(role_config_file=self.roles_config_file_path, error=e)
            self.lgr.warning(err)
            raise ValueError(err)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.roles_config_file_path:
            self.load_roles_config()

    def authorize(self):
        target_endpoint = rest_security.get_endpoint()
        target_method = rest_security.get_http_method()
        roles = self.role_loader.get_roles()
        return self._is_allowed(target_endpoint, target_method, roles) and \
            not self._is_denied(target_endpoint, target_method, roles)

    def _is_allowed(self, target_endpoint, target_method, user_roles):
        return self._evaluate_permission_by_type(target_endpoint,
                                                 target_method, user_roles,
                                                 'allow')

    def _is_denied(self, target_endpoint, target_method, user_roles):
        return self._evaluate_permission_by_type(target_endpoint,
                                                 target_method, user_roles,
                                                 'deny')

    def _evaluate_permission_by_type(self, target_endpoint, target_method,
                                     user_roles, permission_type):
        for role in user_roles:
            role_permissions = self.permissions_by_roles.get(role,
                                                             {'allow': {},
                                                              'deny': {}})
            relevant_permissions = role_permissions.get(permission_type, {})
            if _is_permission_matching(target_endpoint, target_method,
                                       relevant_permissions):
                return True
        return False


def _is_permission_matching(target_endpoint, target_method,
                            configured_permissions):
    for endpoint, methods in configured_permissions.iteritems():
        if _is_endpoint_matching(target_endpoint=target_endpoint,
                                 configured_endpoint=endpoint):
            if _is_method_matching(target_method=target_method,
                                   configured_methods=methods):
                # match!
                return True
    return False


def _is_method_matching(target_method, configured_methods):
    if configured_methods == [ANY]:
        return True
    configured_methods = [value.upper() for value in configured_methods]
    return target_method.upper() in configured_methods


def _is_endpoint_matching(target_endpoint, configured_endpoint):
    if configured_endpoint == ANY:
        return True

    pattern = configured_endpoint.replace('/', '\/').replace('*', '.*') + '$'
    if re.match(pattern, target_endpoint):
        return True
    else:
        # this is so that endpoint "v2/blueprints/*" would match
        # requests to "v2/blueprints"
        if configured_endpoint.endswith('/*'):
            return _is_endpoint_matching(target_endpoint,
                                         configured_endpoint[:-2])
        return False
