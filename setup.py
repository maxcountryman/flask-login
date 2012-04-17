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
    version='0.1.1',
    url='http://bitbucket.org/leafstorm/flask-login/',
    license='MIT',
    author='Matthew Frazier',
    author_email='leafstormrush@gmail.com',
    description='User session management for Flask',
    long_description=__doc__,
    packages=['flaskext'],
    namespace_packages=['flaskext'],
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
    tests_require=['Attest'],
    test_loader='attest:auto_reporter.test_loader',
    test_suite='tests.login.login'
)
