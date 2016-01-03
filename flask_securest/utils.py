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
from itsdangerous import base64_decode
from flask import request

AUTH_HEADER_NAME = 'Authorization'
BASIC_AUTH_PREFIX = 'Basic'
DEFAULT_PASSWORD_HASH = 'plaintext'


def get_instance_class_fqn(instance):
    instance_cls = instance.__class__
    return instance_cls.__module__ + '.' + instance_cls.__name__


def get_class_fqn(clazz):
    return clazz.__module__ + '.' + clazz.__name__


def get_basic_http_authentication_info():
    auth_header = request.headers.get(AUTH_HEADER_NAME)
    if not auth_header:
        raise RuntimeError('Request authentication header "{0}" is empty '
                           'or missing'.format(AUTH_HEADER_NAME))

    auth_header = auth_header.replace(BASIC_AUTH_PREFIX + ' ', '', 1)
    try:
        api_key = base64_decode(auth_header)
        # TODO parse better, with checks and all, this is shaky
    except TypeError:
        pass
    else:
        api_key_parts = api_key.split(':')
        if len(api_key_parts) != 2:
            raise RuntimeError('Invalid {0} header. Header should contain'
                               ' exactly 2 items separated by ":" but '
                               'contains {1} item(s)'.
                               format(AUTH_HEADER_NAME,
                                      len(api_key_parts)))
        request_user_id = api_key_parts[0]
        request_password = api_key_parts[1]
        if not request_user_id or not request_password:
            raise RuntimeError('username or password not found on request')
        return request_user_id, request_password
