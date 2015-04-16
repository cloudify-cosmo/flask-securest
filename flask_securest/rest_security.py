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

from collections import namedtuple
from functools import wraps

from flask import (current_app,
                   abort,
                   request,
                   _request_ctx_stack)
from flask_restful import Resource

from userstores.abstract_userstore import AbstractUserstore
from authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider


AUTH_HEADER_NAME = 'Authorization'
AUTH_TOKEN_HEADER_NAME = 'Authentication-Token'

SECURED_MODE = 'SECUREST_MODE'


class SecuREST(object):

    def __init__(self, app):
        self.app = app

        self.app.config[SECURED_MODE] = True
        self.app.securest_logger = None
        self.app.securest_unauthorized_user_handler = None
        self.app.securest_authentication_providers = []
        self.app.securest_userstore_driver = None
        self.app.request_security_bypass_handler = None

        self.app.before_first_request(validate_configuration)
        self.app.after_request(filter_response_if_needed)

    @property
    def request_security_bypass_handler(self):
        return self.app.request_security_bypass_handler

    @request_security_bypass_handler.setter
    def request_security_bypass_handler(self, request_security_bypass_handler):
        self.app.request_security_bypass_handler = \
            request_security_bypass_handler

    @property
    def unauthorized_user_handler(self):
        return self.app.securest_unauthorized_user_handler

    @unauthorized_user_handler.setter
    def unauthorized_user_handler(self, unauthorized_user_handler):
        self.app.securest_unauthorized_user_handler = unauthorized_user_handler

    @property
    def logger(self):
        return self.app.securest_logger

    @logger.setter
    def logger(self, logger):
        self.app.securest_logger = logger

    def set_userstore_driver(self, userstore):
        """
        Registers the given userstore driver.
        :param userstore: the userstore driver to be set
        """
        if not isinstance(userstore, AbstractUserstore):
            err_msg = 'failed to register userstore driver "{0}", Error: ' \
                      'driver does not inherit "{1}"'\
                .format(get_instance_class_fqn(userstore),
                        get_class_fqn(AbstractUserstore))
            self.app.securest_logger.error(err_msg)
            raise Exception(err_msg)

        self.app.securest_userstore_driver = userstore

    def register_authentication_provider(self, provider):
        """
        Registers the given authentication method.
        :param provider: appends the given authentication provider to the list
         of providers
        NOTE: Pay attention to the order of the registered providers!
        authentication will be attempted on each of the registered providers,
        according to their registration order, until successful.
        """
        if not isinstance(provider, AbstractAuthenticationProvider):
            err_msg = 'failed to register authentication provider "{0}", ' \
                      'Error: provider does not inherit "{1}"'\
                .format(get_instance_class_fqn(provider),
                        get_class_fqn(AbstractAuthenticationProvider))
            self.app.securest_logger.error(err_msg)
            raise Exception(err_msg)

        self.app.securest_authentication_providers.append(provider)


def validate_configuration():
    if not current_app.securest_authentication_providers:
        raise Exception('authentication providers not set')


def filter_response_if_needed(response=None):
    return response


def filter_results(results):
    return results


def auth_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _is_secured_request_context():
            try:
                auth_info = get_auth_info_from_request()
                authenticate(current_app.securest_authentication_providers,
                             auth_info)
            except Exception as e:
                current_app.securest_logger.debug('authentication failed, {0}'
                                                  .format(e))
                handle_unauthorized_user()
            result = func(*args, **kwargs)
            return filter_results(result)
        else:
            # rest security is turned off
            return func(*args, **kwargs)
    return wrapper


def _is_secured_request_context():
    return current_app.config.get(SECURED_MODE) and not \
        (current_app.request_security_bypass_handler and
         current_app.request_security_bypass_handler(request))


def handle_unauthorized_user():
    if current_app.securest_unauthorized_user_handler:
        current_app.securest_unauthorized_user_handler()
    else:
        # TODO verify this ends up in resources.abort_error
        # TODO do this? from flask_restful import abort
        abort(401)


def get_auth_info_from_request():
    user_id = None
    password = None
    token = None

    # TODO remember this is configurable - document
    app_config = current_app.config

    auth_header_name = app_config.get('AUTH_HEADER_NAME', AUTH_HEADER_NAME)
    if auth_header_name:
        auth_header = request.headers.get(auth_header_name)

    auth_token_header_name = app_config.get('AUTH_TOKEN_HEADER_NAME',
                                            AUTH_TOKEN_HEADER_NAME)
    if auth_token_header_name:
        token = request.headers.get(auth_token_header_name)

    if not auth_header and not token:
        raise Exception('Failed to get authentication information from '
                        'request, headers not found: {0}, {1}'
                        .format(auth_header_name, auth_token_header_name))

    if auth_header:
        auth_header = auth_header.replace('Basic ', '', 1)
        try:
            from itsdangerous import base64_decode
            api_key = base64_decode(auth_header)
            # TODO parse better, with checks and all, this is shaky
        except TypeError:
            pass
        else:
            api_key_parts = api_key.split(':')
            user_id = api_key_parts[0]
            password = api_key_parts[1]

    auth_info = namedtuple('auth_info_type',
                           ['user_id', 'password', 'token'])

    return auth_info(user_id, password, token)


def authenticate(authentication_providers, auth_info):
    user = None

    userstore_driver = current_app.securest_userstore_driver
    for auth_provider in authentication_providers:
        try:
            if userstore_driver:
                current_app.securest_logger.debug(
                    'attempting authentication with provider "{0}" '
                    'and userstore: "{1}"'.format(
                        get_instance_class_fqn(auth_provider),
                        get_instance_class_fqn(userstore_driver)))
            else:
                current_app.securest_logger.debug(
                    'attempting authentication with provider "{0}" and '
                    'without userstore'.format(
                        get_instance_class_fqn(auth_provider)))

            user = auth_provider.authenticate(
                auth_info, userstore_driver)
            current_app.securest_logger.debug('authentication succeeded')
            break
        except Exception as e:
            current_app.securest_logger.debug('authentication failed, {0}'
                                              .format(e))
            continue  # try the next authentication method until successful

    if not user:
        raise Exception('Unauthorized')

    set_request_user(user)


def _get_request_context():
    request_ctx = _request_ctx_stack.top
    if request_ctx is None:
        raise RuntimeError('working outside of request context')
    return request_ctx


def get_request_user():
    return getattr(_get_request_context(), 'user')


def set_request_user(user):
    _get_request_context().user = user


def get_instance_class_fqn(instance):
    instance_cls = instance.__class__
    return instance_cls.__module__ + '.' + instance_cls.__name__


def get_class_fqn(clazz):
    return clazz.__module__ + '.' + clazz.__name__


class SecuredResource(Resource):
    secured = True
    method_decorators = [auth_required]
