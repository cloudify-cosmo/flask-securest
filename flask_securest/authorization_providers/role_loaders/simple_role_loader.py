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

from flask.ext.securest.authorization_providers.role_loaders.\
    abstract_role_loader import AbstractRoleLoader
from flask_securest import rest_security


class SimpleRoleLoader(AbstractRoleLoader):

    def get_roles(self):
        userstore = current_app.securest_userstore_driver
        principals = rest_security.get_principals_list() or []
        roles = set()
        for principal in principals:
            for role in userstore.get_roles(principal) or []:
                roles.add(role)

        return roles
