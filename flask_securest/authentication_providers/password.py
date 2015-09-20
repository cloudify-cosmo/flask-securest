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

from passlib.context import CryptContext
from flask import request
from flask_securest.authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider

AUTH_HEADER_NAME = 'Authorization'
BASIC_AUTH_PREFIX = 'Basic'
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
        self.request_user_id = None
        self.request_password = None

    def _retrieve_request_credentials(self):
        auth_header = request.headers.get(AUTH_HEADER_NAME)
        if not auth_header:
            raise RuntimeError('Request authentication header "{0}" is empty '
                               'or missing'.format(AUTH_HEADER_NAME))

        auth_header = auth_header.replace(BASIC_AUTH_PREFIX + ' ', '', 1)
        try:
            from itsdangerous import base64_decode
            api_key = base64_decode(auth_header)
            # TODO parse better, with checks and all, this is shaky
        except TypeError:
            pass
        else:
            api_key_parts = api_key.split(':')
            self.request_user_id = api_key_parts[0]
            self.request_password = api_key_parts[1]
            if not self.request_user_id or not self.request_password:
                raise RuntimeError('username or password not found on request')

    def authenticate(self, userstore):
            self._retrieve_request_credentials()
            user_object = userstore.get_user(self.request_user_id)
            if not user_object:
                # user not found
                raise Exception('authentication of {0} failed'.
                                format(self.request_user_id))

            verified = self.crypt_ctx.verify(self.request_password,
                                             user_object.password)
            if not verified or not user_object.is_active():
                # wrong password or disabled user
                raise Exception('authentication of {0} failed'.
                                format(self.request_user_id))

            return user_object


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
