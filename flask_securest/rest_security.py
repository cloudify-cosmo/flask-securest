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

import StringIO
from collections import OrderedDict
from functools import wraps

from flask import (current_app,
                   abort,
                   request,
                   g as flask_request_globals)
from flask_restful import Resource

from flask_securest import utils
from flask_securest.exceptions import FlaskSecuRESTException, \
    AuthenticationException, AuthorizationException
from flask_securest.userstores.abstract_userstore import AbstractUserstore
from flask_securest.authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider
from flask_securest.authorization_providers.abstract_authorization_provider \
    import AbstractAuthorizationProvider


SECURED_MODE = 'app_secured'
SECURITY_CTX_HTTP_METHOD = 'http_method'
SECURITY_CTX_ENDPOINT = 'endpoint'
SECURITY_CTX_USERNAME = 'username'
SECURITY_CTX_PRINCIPALS = 'principals'


class SecuREST(object):

    def __init__(self, app):
        self.app = app

        self.app.config[SECURED_MODE] = True
        self.app.securest_logger = None
        self.app.securest_unauthorized_user_handler = None
        self.app.securest_authentication_providers = OrderedDict()
        self.app.securest_authorization_provider = None
        self.app.securest_userstore_driver = None
        self.app.skip_auth_hook = None

        self.app.before_first_request(_validate_configuration)
        self.app.before_request(_clean_security_context)

    @property
    def skip_auth_hook(self):
        return self.app.skip_auth_hook

    @skip_auth_hook.setter
    def skip_auth_hook(self, value):
        self.app.skip_auth_hook = value

    @property
    def unauthorized_user_handler(self):
        return self.app.securest_unauthorized_user_handler

    @unauthorized_user_handler.setter
    def unauthorized_user_handler(self, value):
        self.app.securest_unauthorized_user_handler = value

    @property
    def logger(self):
        return self.app.securest_logger

    @logger.setter
    def logger(self, logger):
        self.app.securest_logger = logger

    @property
    def userstore_driver(self):
        return self.app.securest_userstore_driver

    @userstore_driver.setter
    def userstore_driver(self, userstore):
        """
        Registers the given userstore driver.
        :param userstore: the userstore driver to be set
        """
        if not isinstance(userstore, AbstractUserstore):
            err_msg = 'failed to register userstore driver "{0}", Error: ' \
                      'driver does not inherit "{1}"'\
                .format(utils.get_instance_class_fqn(userstore),
                        utils.get_class_fqn(AbstractUserstore))
            _log(self.app.securest_logger, 'critical', err_msg)
            raise FlaskSecuRESTException(err_msg)

        self.app.securest_userstore_driver = userstore

    def register_authentication_provider(self, name, provider):
        """
        Registers the given authentication method.
        :param name: A unique name for the authentication provider, required
         for logging
        :param provider: appends the given authentication provider to the list
         of providers
        NOTE: Pay attention to the order of the registered providers!
        authentication will be attempted on each of the registered providers,
        according to their registration order, until successful.
        """
        if not isinstance(provider, AbstractAuthenticationProvider):
            err_msg = 'failed to register authentication provider "{0}", ' \
                      'Error: provider does not inherit "{1}"'\
                .format(utils.get_instance_class_fqn(provider),
                        utils.get_class_fqn(AbstractAuthenticationProvider))
            _log(self.app.securest_logger, 'critical', err_msg)
            raise FlaskSecuRESTException(err_msg)

        self.app.securest_authentication_providers[name] = provider

    @property
    def authorization_provider(self):
        return self.app.securest_authorization_provider

    @authorization_provider.setter
    def authorization_provider(self, provider):
        """
        Registers the given authorization provider.
        :param provider: the authorization provider to be set
        """
        if not isinstance(provider, AbstractAuthorizationProvider):
            err_msg = 'failed to register authorization provider "{0}", ' \
                      'Error: provider does not inherit "{1}"' \
                .format(utils.get_instance_class_fqn(provider),
                        utils.get_class_fqn(AbstractAuthorizationProvider))
            _log(self.app.securest_logger, 'critical', err_msg)
            raise FlaskSecuRESTException(err_msg)

        self.app.securest_authorization_provider = provider


def _validate_configuration():
    if not current_app.securest_authentication_providers:
        raise FlaskSecuRESTException('authentication providers not set')


def _clean_security_context():
    flask_request_globals.security_context = {
        SECURITY_CTX_HTTP_METHOD: None,
        SECURITY_CTX_ENDPOINT: None,
        SECURITY_CTX_USERNAME: None,
        SECURITY_CTX_PRINCIPALS: None
    }


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _is_secured_request_context():
            try:
                _set_security_context_value(SECURITY_CTX_ENDPOINT,
                                            request.path)
                _set_security_context_value(SECURITY_CTX_HTTP_METHOD,
                                            request.method)
                authenticate()
                if current_app.securest_authorization_provider:
                    authorize()
            except Exception as e:
                _log(current_app.securest_logger, 'error', e)
                handle_unauthorized_user()
            return func(*args, **kwargs)
        else:
            return func(*args, **kwargs)
    return wrapper


def _is_secured_request_context():
    return current_app.config.get(SECURED_MODE) and not \
        (current_app.skip_auth_hook and
         current_app.skip_auth_hook(request))


def handle_unauthorized_user():
    if current_app.securest_unauthorized_user_handler:
        current_app.securest_unauthorized_user_handler()
    else:
        abort(401)


def get_request_origin():
    request_origin_ip = request.remote_addr
    if request_origin_ip:
        request_origin = '[{0}]'.format(request_origin_ip)
    else:
        request_origin = '[unknown]'
    return request_origin


def authenticate():
    username = None
    error_msg = StringIO.StringIO()
    request_origin = get_request_origin()
    userstore_driver = current_app.securest_userstore_driver
    authentication_providers = current_app.securest_authentication_providers
    for auth_method, auth_provider in authentication_providers.iteritems():
        try:
            username = auth_provider.authenticate(userstore_driver)
            if not username:
                raise AuthenticationException('return username is empty')
            # TODO the user obj might not have a 'username' field,
            # we should use smarter logging
            msg = 'user "{0}" authenticated successfully from host {1}, ' \
                  'authentication provider: {2}'\
                .format(username, request_origin, auth_method)
            _log(current_app.securest_logger, 'info', msg)
            break
        except Exception as e:
            if not error_msg.getvalue():
                error_msg.write('User unauthorized; '
                                'user tried to login from host {0};'
                                '\nall authentication methods failed:'
                                .format(request_origin))
            error_msg.write('\n{0} authenticator: {1}'
                            .format(auth_method, e))
            continue  # try the next authentication method until successful

    if not username:
        raise AuthenticationException(error_msg.getvalue())

    _set_security_context_value(SECURITY_CTX_USERNAME, username)
    _set_security_context_value(SECURITY_CTX_PRINCIPALS,
                                _get_all_principals_for_current_user())


def authorize():
    authorization_provider = current_app.securest_authorization_provider
    is_authorized = authorization_provider.authorize()
    if is_authorized:
        msg = 'user "{0}" is authorized to call {1} on {2}'.format(
            get_username(), get_http_method(), get_endpoint())
        _log(current_app.securest_logger, 'info', msg)
    else:
        raise AuthorizationException('User {0} is not authorized to call {1}'
                                     ' on {2}'.format(get_username(),
                                                      get_http_method(),
                                                      get_endpoint()))


def _get_all_principals_for_current_user():
    if current_app.securest_userstore_driver:
        principals_list = current_app.securest_userstore_driver.\
            get_all_principals_for_user(get_username())
    else:
        principals_list = get_username()

    return principals_list


def _get_security_context_value(key):
    return flask_request_globals.security_context.get(key)


def _set_security_context_value(key, value):
    flask_request_globals.security_context[key] = value


def get_username():
    return _get_security_context_value(SECURITY_CTX_USERNAME)


def get_endpoint():
    return _get_security_context_value(SECURITY_CTX_ENDPOINT)


def get_http_method():
    return _get_security_context_value(SECURITY_CTX_HTTP_METHOD)


def get_principals_list():
    return _get_security_context_value(SECURITY_CTX_PRINCIPALS)


def _log(logger, method, message):
    if logger:
        logging_method = getattr(logger, method)
        logging_method(message)


class SecuredResource(Resource):
    secured = True
    method_decorators = [auth_required]
