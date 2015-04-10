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


from flask import current_app, request
from itsdangerous import base64_decode
from passlib.context import CryptContext

from flask_securest.authentication_providers.abstract_authentication_provider\
    import AbstractAuthenticationProvider


DEFAULT_AUTH_HEADER_NAME = 'Authorization'
DEFAULT_PASSWORD_HASH = 'plaintext'

PASSWORD_SCHEMES = [
    'bcrypt',
    'des_crypt',
    'pbkdf2_sha256',
    'pbkdf2_sha512',
    'sha256_crypt',
    'sha512_crypt',
    'plaintext'
    ]

DEPRECATED_PASSWORD_SCHEMES = ['auto']


class PasswordAuthenticator(AbstractAuthenticationProvider):

    def __init__(self, password_hash=DEFAULT_PASSWORD_HASH):
        self.crypt_ctx = _get_crypt_context(password_hash)

    def authenticate(self, userstore):
        user_id, password = _get_auth_info_from_request()
        user = userstore.get_user(user_id)

        if not user:
            raise Exception('user not found')
        if not user.password:
            raise Exception('password is missing or empty')

        if not self.crypt_ctx.verify(password, user.password):
            raise Exception('wrong password')
        if not user.is_active():
            raise Exception('user not active')

        return user


def _get_auth_info_from_request():
    auth_header_name = current_app.config.get('AUTH_HEADER_NAME',
                                              DEFAULT_AUTH_HEADER_NAME)
    auth_header = request.headers.get(auth_header_name)
    if not auth_header:
        raise Exception('Authentication header not found on request: {0}'
                        .format(auth_header_name))

    # removing "Basic " prefix if found (i.e. basic http auth header)
    auth_header = auth_header.replace('Basic ', '', 1)
    try:
        api_key = base64_decode(auth_header)
    except TypeError as e:
        raise Exception('Failed to read authentication data from request, {0}'
                        .format(e))

    # TODO parse better, with checks and all, this is shaky
    api_key_parts = api_key.split(':')
    user_id = api_key_parts[0]
    password = api_key_parts[1]

    return user_id, password


def _get_crypt_context(password_hash):
    if password_hash not in PASSWORD_SCHEMES:
        allowed = (', '.join(PASSWORD_SCHEMES[:-1]) +
                   ' and ' + PASSWORD_SCHEMES[-1])
        raise ValueError("Invalid password hash {0}. Allowed values are {1}"
                         .format(password_hash, allowed))
    try:
        crypt_ctx = CryptContext(schemes=PASSWORD_SCHEMES,
                                 default=password_hash,
                                 deprecated=DEPRECATED_PASSWORD_SCHEMES)
    except Exception as e:
        print 'Failed to initialize password crypt context: ', e
        raise

    return crypt_ctx
