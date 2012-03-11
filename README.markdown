# Flask-Login

Flask-Login provides user session management for Flask. It handles the common
tasks of logging in, logging out, and remembering your users' sessions over
extended periods of time.

Flask-Login is not bound to any particular database system or permissions
model. The only requirement is that your user objects implement a few methods,
and that you provide a callback to the extension capable of loading users from
their ID.

## Installation

Install the extension with one of the following commands:

    $ easy_install flask-login

or alternatively if you have pip installed:

    $ pip install flask-login
