import os.path
import yaml
from flask.ext.securest.userstores.abstract_userstore import AbstractUserstore
from flask.ext.securest.models import User, Role

USERNAME = 'username'
PASSWORD = 'password'
EMAIL = 'email'
ROLES = 'roles'

RESOURCES_PATH = os.path.dirname(__file__) + '/../resources'


class FileUserstore(AbstractUserstore):

    def __init__(self, userstore_file, identifying_attribute):
        print '***** INITING class FileUserstore with identifying_attr {0}' \
              ' and file_location {1}'.format(identifying_attribute,
                                              userstore_file)
        self._identifying_attribute = identifying_attribute
        abs_file_location = RESOURCES_PATH + "/" + userstore_file
        if not os.path.isfile(abs_file_location):
            raise ValueError('file not found: {0}'.format(abs_file_location))

        with open(abs_file_location) as users_file:
            self.users = yaml.load(users_file.read())

    def get_user(self, user_identifier):
        user_obj = None

        print '***** getting user where {0} = {1}'\
            .format(self._identifying_attribute, user_identifier)

        if not user_identifier:
            raise ValueError('user identifier is missing or empty')

        for user_entry in self.users.itervalues():
            if user_entry.get(self._identifying_attribute) == user_identifier:
                print '***** found user!'
                # a matching user was found, return as a User object
                user_obj = FileUserstore._create_user_object(user_entry)
                break

        return user_obj

    @staticmethod
    def _create_user_object(user_dict):

        roles = []
        for role_name in user_dict[ROLES]:
            roles.append(Role(role_name))

        return User(user_dict[USERNAME], user_dict[PASSWORD],
                    user_dict[EMAIL], roles, active=True)
