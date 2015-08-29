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
from flask import current_app


class SimpleUserstore(AbstractUserstore):

    def __init__(self, userstore, identifying_attribute):
        self._identifying_attribute = identifying_attribute
        self.users = userstore

    def get_user(self, user_identifier):
        user_obj = {}

        if not user_identifier:
            raise ValueError('user identifier is missing or empty')

        user_entry = self.find_user(user_identifier)
        if user_entry:
            # a matching entry was found.
            # if the user is not disabled - use this entry
            if user_entry.get('is_active', True):
                user_obj = user_entry

        return user_obj

    def get_all_principals_for_user(self, user_identifier):
        current_app.logger.info('***** '
                                'starting simple.get_all_principals_for_user')
        principals = []
        user_entry = self.find_user(user_identifier)
        current_app.logger.info('***** user_entry is {0}'.format(user_entry))
        if user_entry:
            current_app.logger.info('***** appending principal: {0}'.
                                    format(user_identifier))
            principals.append(user_identifier)
            current_app.logger.info('***** looping groups...')
            groups = user_entry.get('groups')
            if groups:
                for group in user_entry.get('groups'):
                    current_app.logger.info('***** appending group: {0}'.
                                            format(group))
                    principals.append(group)

        return principals

    def find_user(self, user_identifier):
        matching_entry = None
        for user_entry in self.users.itervalues():
            if user_entry.get(self._identifying_attribute) == user_identifier:
                matching_entry = user_entry
                break
        return matching_entry
