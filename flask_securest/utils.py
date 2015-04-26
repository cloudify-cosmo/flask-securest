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

import socket


def get_ip_list_by_hostname(hostname):
    name, aliaslist, addresslist = socket.gethostbyname(hostname)
    return addresslist


def get_hostname_by_ip(ip_address):
    name, aliaslist, addresslist = socket.gethostbyaddr(ip_address)
    return name


def log(logger, method, message):
    if logger:
        logging_method = getattr(logger, method)
        logging_method(message)


def get_instance_class_fqn(instance):
    instance_cls = instance.__class__
    return instance_cls.__module__ + '.' + instance_cls.__name__


def get_class_fqn(clazz):
    return clazz.__module__ + '.' + clazz.__name__
