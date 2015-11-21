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


import ldap
from flask_securest.authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider


class LDAPAuthenticationProvider(AbstractAuthenticationProvider):
    def __init__(self, directory_url):
        self.directory_url = directory_url

    def authenticate(self):
        username, password = self._retrieve_credentials_from_request()
        # initialize connection to the LDAP server
        try:
            conn = ldap.initialize(self.directory_url)
        except Exception as e:
            raise Exception(
                'Failed to initialize LDAP connection to {0}; {1}'
                .format(self.directory_url, str(e)))

        # trying to bind with the given user and password
        try:
            conn.bind_s(username, password)
            conn.unbind()
            return username
        except Exception as e:
            raise Exception(
                'Failed to authenticate user {0}; {1}'
                .format(username, str(e)))
