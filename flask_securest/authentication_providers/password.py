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
from flask_securest import utils
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

    def authenticate(self, userstore):
        request_user_id, request_password = \
            utils.get_basic_http_authentication_info()
        stored_user = userstore.get_user(request_user_id)
        if not stored_user:
            # user not found
            raise Exception('authentication of user "{0}" failed'.
                            format(request_user_id))

        verified = self.crypt_ctx.verify(request_password,
                                         stored_user['password'])
        if not verified:
            # wrong password
            raise Exception('authentication of user "{0}" failed'.
                            format(request_user_id))

        return stored_user['username']


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
