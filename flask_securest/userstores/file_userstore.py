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
import os
import yaml
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from flask_securest.userstores import simple

LOGGER_NAME = 'flask-securest'


class FileUserstore(simple.SimpleUserstore, FileSystemEventHandler):

    def __init__(self, userstore_file_path):
        self.lgr = logging.getLogger(name=LOGGER_NAME)
        self.userstore_file_path = userstore_file_path
        self.users = None
        self.groups = None
        self.observer = Observer()
        self.observer.schedule(self,
                               path=os.path.dirname(
                                   os.path.abspath(userstore_file_path)),
                               recursive=False)
        self.load_userstore()
        self.observer.start()

    def on_modified(self, event):
        if event.src_path == self.userstore_file_path:
            self.load_userstore()

    def load_userstore(self):
        '''
        This function updates the userstore in-case the file holding the
        data was modified.
        :return:
        '''
        self.lgr.info('Loading userstore from {file}.'
                      .format(file=self.userstore_file_path))
        try:
            with open(self.userstore_file_path) as f:
                userstore = yaml.safe_load(f.read())
        except (yaml.ParserError, IOError) as e:
            err = 'Failed parsing {userstore_file} file. Users and groups ' \
                  'will not be loaded. Error: {error}.'\
                  .format(userstore_file=self.userstore_file_path,
                          error=str(e))
            self.lgr.warning(err)
            raise ValueError(err)
        if isinstance(userstore, dict):
            if 'users' in userstore.keys():
                self.users = userstore.get('users')
            else:
                err = 'Users not found in {file} yaml. Failed loading users.'\
                      .format(file=self.userstore_file_path)
                self.lgr.warning(err)
                raise ValueError(err)

            self.groups = userstore.get('groups')
        else:
            err = '{userstore_file} yaml is not a valid dict. Userstore ' \
                  'file will not be loaded.'\
                  .format(userstore_file=self.userstore_file_path)
            self.lgr.warning(err)
            raise ValueError()
        self.lgr.info('Loading of userstore ended successfully.')
