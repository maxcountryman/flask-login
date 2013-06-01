"""
Flask-Login
-----------
Flask-Login provides user session management for Flask. It handles the common
tasks of logging in, logging out, and remembering your users' sessions over
extended periods of time.

Flask-Login is not bound to any particular database system or permissions
model. The only requirement is that your user objects implement a few methods,
and that you provide a callback to the extension capable of loading users from
their ID.

Links
`````
* `documentation <http://packages.python.org/Flask-Login>`_
* `development version
  <https://github.com/maxcountryman/flask-login>`_


"""
from setuptools import setup


setup(
    name='Flask-Login',
    version='0.2.0-dev',
    url='https://github.com/maxcountryman/flask-login',
    license='MIT',
    author='Matthew Frazier',
    author_email='leafstormrush@gmail.com',
    description='User session management for Flask',
    long_description=__doc__,
    py_modules=['flask_login'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    tests_require=['nose'],
    test_suite='nose.collector'
)
