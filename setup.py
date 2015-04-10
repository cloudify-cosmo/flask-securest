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

from setuptools import setup


setup(
    name='Flask-SecuREST',
    version='0.5',
    # url='http://example.com/flask-securest/',
    # license='BSD',
    author='Noa Kuperberg',
    author_email='noak@gigaspaces.com',
    # description='Securing Flask REST applications',
    # long_description=__doc__,
    # if you would be using a package instead use packages instead
    # of py_modules:
    packages=['flask_securest',
              'flask_securest.authentication_providers',
              'flask_securest.userstores'],
    # zip_safe=False,
    # include_package_data=True,
    # platforms='any',
    install_requires=[
        'Flask>=0.9',
        'Flask-RESTful>=0.2.5',
        'passlib>=1.6.2',
        'itsdangerous>=0.24',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        # 'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
