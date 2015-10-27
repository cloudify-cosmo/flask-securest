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

    def __init__(self, userstore, identifying_attribute):
        self._identifying_attribute = identifying_attribute
        self.users = userstore

    def get_user(self, username):
        if not username:
            raise ValueError('username is missing or empty')

        return self.find_user(username) or {}

    def find_user(self, username):
        matching_entry = None
        for user_entry in self.users.itervalues():
            if user_entry.get(self._identifying_attribute) == username:
                matching_entry = user_entry
                break
        return matching_entry
