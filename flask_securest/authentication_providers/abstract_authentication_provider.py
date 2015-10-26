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

import abc


class AbstractAuthenticationProvider(object):
    """
    This class is abstract and should be inherited by concrete
    implementations of authentication providers.
    The only mandatory implementation is of authenticate, which is expected
    to return true/false
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def authenticate(self, userstore=None):
        raise NotImplementedError
