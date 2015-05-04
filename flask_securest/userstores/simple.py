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
from flask.ext.securest.models import User

USERNAME = 'username'
PASSWORD = 'password'
EMAIL = 'email'


class SimpleUserstore(AbstractUserstore):

    def __init__(self, userstore, identifying_attribute):
        self._identifying_attribute = identifying_attribute
        self.users = userstore

    def get_user(self, user_identifier):
        user_obj = None

        if not user_identifier:
            raise ValueError('user identifier is missing or empty')

        for user_entry in self.users.itervalues():
            if user_entry.get(self._identifying_attribute) == user_identifier:
                # a matching user was found, return as a User object
                user_obj = SimpleUserstore._create_user_object(user_entry)
                break

        return user_obj

    @staticmethod
    def _create_user_object(user_dict):
        return User(user_dict[USERNAME], user_dict[PASSWORD],
                    user_dict[EMAIL], active=True)
