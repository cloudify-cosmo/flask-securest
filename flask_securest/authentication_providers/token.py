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

# TODO select the correct serializer, could be
# URLSafeTimedSerializer
from itsdangerous import \
    TimedJSONWebSignatureSerializer, SignatureExpired, BadSignature

from flask_securest import rest_security
from flask_securest.models import AnonymousUser
from abstract_authentication_provider import AbstractAuthenticationProvider


class TokenAuthenticator(AbstractAuthenticationProvider):

    def __init__(self, secret_key, expires_in=600):
        self._secret_key = secret_key
        self._serializer = TimedJSONWebSignatureSerializer(self._secret_key,
                                                           expires_in)

    def generate_auth_token(self):
        current_user = rest_security.get_request_user()
        if not current_user:
            raise Exception('Failed to generate token, user not found on the '
                            'current request')

        if isinstance(current_user, AnonymousUser):
            raise Exception('Token generation is not allowed for anonymous '
                            'users')

        return self._serializer.dumps({'username': current_user.username})

    def authenticate(self, auth_info, userstore):
        token = auth_info.token

        if not token:
            raise Exception('token is missing or empty')

        try:
            open_token = self._serializer.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token

        # TODO should the identity field in the token be configurable?
        username = open_token['username']
        user = userstore.get_user(username)
        # user = userstore.find_user(email=data['email'])
        # for the SQLAlchemy model: user = User.query.get(data['id'])
        return user
