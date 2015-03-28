# TODO select the correct serializer, could be
# URLSafeTimedSerializer
from itsdangerous import \
    TimedJSONWebSignatureSerializer, SignatureExpired, BadSignature

from flask_securest import rest_security
from flask_securest.rest_security import AnonymousUser
from abstract_authentication_provider import AbstractAuthenticationProvider


class TokenAuthenticator(AbstractAuthenticationProvider):

    def __init__(self, secret_key, expires_in=600):
        print '***** INITING TokenAuthenticator'
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
        print '***** attempting to authenticate using TokenAuthenticator'
        token = auth_info.token
        print '***** verifying auth token: ', token

        if not token:
            raise Exception('token is missing or empty')

        try:
            print '***** attempting to deserialize the token'
            open_token = self._serializer.loads(token)
        except SignatureExpired:
            print '***** exception SignatureExpired, returning None'
            return None  # valid token, but expired
        except BadSignature:
            print '***** exception BadSignature, returning None'
            return None  # invalid token

        # TODO should the identity field in the token be configurable?
        username = open_token['username']
        print '***** token loaded, username in token is: ', username
        print '***** getting user from userstore: ', userstore
        user = userstore.get_user(username)
        # user = userstore.find_user(email=data['email'])
        # for the SQLAlchemy model: user = User.query.get(data['id'])
        return user
