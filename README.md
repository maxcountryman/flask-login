# Flask-Login

[![build status](https://secure.travis-ci.org/maxcountryman/flask-login.png?branch=master)](https://travis-ci.org/#!/maxcountryman/flask-login)

Flask-Login provides user session management for Flask. It handles the common
tasks of logging in, logging out, and remembering your users' sessions over
extended periods of time.

Flask-Login is not bound to any particular database system or permissions
model. The only requirement is that your user objects implement a few methods,
and that you provide a callback to the extension capable of loading users from
their ID.

## Installation

Install the extension with one of the following commands:

```sh
$ easy_install flask-login
```

or alternatively if you have pip installed:

```sh
$ pip install flask-login
```

## Contributing

We welcome contributions! If you would like to hack on Flask-Login, please
follow these steps:

1. Fork this repository
2. Make your changes
3. Install the requirements in `dev-requirements.txt`
4. Submit a pull request after running `make check` (ensure it does not error!)

Please give us adequate time to review your submission. Thanks!
