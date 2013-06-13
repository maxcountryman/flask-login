'''
    Flask-Login
    -----------

    Flask-Login provides user session management for Flask. It handles the
    common tasks of logging in, logging out, and remembering your users'
    sessions over extended periods of time.

    Flask-Login is not bound to any particular database system or permissions
    model. The only requirement is that your user objects implement a few
    methods, and that you provide a callback to the extension capable of
    loading users from their ID.

    Links
    `````
    * `documentation <http://packages.python.org/Flask-Login>`_
    * `development version
    <https://github.com/maxcountryman/flask-login>`_
'''
import os
import sys

from setuptools import setup

if sys.argv[-1] == 'test':
    status = os.system('make check')
    status >>= 8
    sys.exit(status)


def get_version(version_tuple):
    if not isinstance(version_tuple[-1], int):
        return '.'.join(map(str, version_tuple[:-1])) + version_tuple[-1]
    return '.'.join(map(str, version_tuple))

module_path = os.path.join(os.path.dirname(__file__), 'flask_login.py')
version_line = list(filter(lambda l: l.startswith('__version_info__'), open(module_path)))[0]

VERSION = get_version(eval(version_line.split('=')[-1]))

setup(name='Flask-Login',
      version=VERSION,
      url='https://github.com/maxcountryman/flask-login',
      license='MIT',
      author='Matthew Frazier',
      author_email='leafstormrush@gmail.com',
      description='User session management for Flask',
      long_description=__doc__,
      py_modules=['flask_login'],
      zip_safe=False,
      platforms='any',
      install_requires=['Flask'],
      classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
        ])
