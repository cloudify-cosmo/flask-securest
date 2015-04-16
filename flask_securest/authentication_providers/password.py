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
from abstract_authentication_provider import AbstractAuthenticationProvider

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

    def authenticate(self, auth_info, userstore):
        if not auth_info.user_id or not auth_info.password:
            raise Exception('username or password not found on request')

        user_id = auth_info.user_id
        user = userstore.get_user(user_id)

        if not user:
            raise Exception('user not found')
        if not user.password:
            raise Exception('password is missing or empty')

        if not self.crypt_ctx.verify(auth_info.password, user.password):
            raise Exception('wrong password')
        if not user.is_active():
            raise Exception('user not active')

        return user


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
