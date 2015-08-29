
class FlaskSecuRESTException(Exception):
    def __init__(self, *args, **kwargs):
        super(FlaskSecuRESTException, self).__init__(*args, **kwargs)


class AuthenticationException(FlaskSecuRESTException):
    def __init__(self, *args, **kwargs):
        super(AuthenticationException, self).__init__(*args, **kwargs)


class AuthorizationException(FlaskSecuRESTException):
    def __init__(self, *args, **kwargs):
        super(AuthorizationException, self).__init__(*args, **kwargs)
