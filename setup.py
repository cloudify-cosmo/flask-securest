"""
Flask-SQLite3
-------------

This is the description for that library
"""
from setuptools import setup


setup(
    name='Flask-SecuREST',
    version='0.5',
    # url='http://example.com/flask-securest/',
    # license='BSD',
    author='noak',
    author_email='noak@gigaspaces.com',
    # description='Securing Flask REST applications',
    # long_description=__doc__,
    # if you would be using a package instead use packages instead
    # of py_modules:
    packages=['flask_securest',
              'flask_securest.authentication_providers',
              'flask_securest.userstores'],
    package_data={
        'flask_securest': ['resources/users.yaml'],
        },
    # zip_safe=False,
    # include_package_data=True,
    # platforms='any',
    install_requires=[
        'Flask>=0.9',
        'Flask-RESTful',
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
