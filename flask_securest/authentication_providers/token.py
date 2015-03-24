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

from itsdangerous import \
    URLSafeTimedSerializer, SignatureExpired, BadSignature
from abstract_authentication_provider import AbstractAuthenticationProvider


class TokenAuthenticator(AbstractAuthenticationProvider):

    def __init__(self, secret_key, expiration):
        print '***** INITING TokenAuthenticator'
        self._secret_key = secret_key
        self._expiration = expiration

    def authenticate(self, auth_info, userstore):
        print '***** attempting to authenticate using TokenAuthenticator'
        token = auth_info.token
        # current_app = flask_globals.current_app
        print '***** verifying auth token: ', token

        if not token:
            raise ValueError('token is missing or empty')

        token_data = token.open_token(token=token, secret_key=self._secret_key)
        if not token_data:
            raise Exception('Unauthorized')

        print '***** token loaded successfully, user id from token is: ', \
            token_data['user_id']
        # TODO should the identity field in the token be configurable?
        user_id = token_data['user_id']
        print '***** getting user from userstore: ', userstore
        user = userstore.get_user(user_id)
        # compare passwords, if they don't match - the token is not valid
        if not user.password \
                or user.password != token_data['user_password']:
            raise Exception('Unauthorized')

        return user


def generate_token(user_id, user_password, secret_key, expiration):
    serializer = URLSafeTimedSerializer(secret_key, expires_in=expiration)
    return serializer.dumps({'user_id': user_id,
                             'user_password': user_password})


def open_token(token, secret_key, expiration):
    token_data = None
    serializer = URLSafeTimedSerializer(secret_key, expires_in=expiration)

    try:
        print '***** attempting to deserialize the token'
        token_data = serializer.loads(token)
    except SignatureExpired:
        print '***** exception SignatureExpired, returning None'
        # valid token, but expired
    except BadSignature:
        print '***** exception BadSignature, returning None'
        # invalid token

    return token_data
