from itsdangerous import \
    URLSafeTimedSerializer, SignatureExpired, BadSignature
from abstract_authentication_provider import AbstractAuthenticationProvider


class TokenAuthenticator(AbstractAuthenticationProvider):

    def __init__(self, secret_key):
        print '***** INITING TokenAuthenticator'
        self._secret_key = secret_key

    def authenticate(self, auth_info, userstore):
        print '***** attempting to authenticate using TokenAuthenticator'
        token = auth_info.token
        # current_app = flask_globals.current_app
        print '***** verifying auth token: ', token

        if not token:
            raise Exception('token is missing or empty')

        serializer = URLSafeTimedSerializer(self._secret_key)

        try:
            print '***** attempting to deserialize the token'
            open_token = serializer.loads(token)
        except SignatureExpired:
            print '***** exception SignatureExpired, returning None'
            return None  # valid token, but expired
        except BadSignature:
            print '***** exception BadSignature, returning None'
            return None  # invalid token

        print '***** token loaded successfully, user email from token is: ', \
            open_token['email']
        # TODO should the identity field in the token be configurable?
        user_id = open_token['user_id']
        print '***** getting user from userstore: ', userstore
        user = userstore.get_user(user_id)
        # user = userstore.find_user(email=data['email'])
        # for the SQLAlchemy model: user = User.query.get(data['id'])
        return user
