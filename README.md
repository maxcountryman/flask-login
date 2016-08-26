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

## Usage

Once installed, the Flask-Login is easy to use. Let's walk through setting up
a basic application. Also please note that this is a very basic guide: we will
be taking shortcuts here that you should never take in a real application.

To begin we'll set up a Flask app:

```python
import flask

app = flask.Flask(__name__)
app.secret_key = 'super secret string'  # Change this!
```

Flask-Login works via a login manager. To kick things off, we'll set up the
login manager by instantiating it and telling it about our Flask app:

```python
import flask_login

login_manager = flask_login.LoginManager()

login_manager.init_app(app)
```

To keep things simple we're going to use a dictionary to represent a database
of users. In a real application, this would be an actual persistence layer.
However it's important to point out this is a feature of Flask-Login: it
doesn't care how your data is stored so long as you tell it how to retrieve it!

```python
# Our mock database.
users = {'foo@bar.tld': {'pw': 'secret'}}
```

We also need to tell Flask-Login how to load a user from a Flask request and
from its session. To do this we need to define our user object, a
`user_loader` callback, and a `request_loader` callback.

```python
class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):
    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    if email not in users:
        return

    user = User()
    user.id = email

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    user.is_authenticated = request.form['pw'] == users[email]['pw']

    return user
```

Now we're ready to define our views. We can start with a login view, which will
populate the session with authentication bits. After that we can define a view
that requires authentication.

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':
        return '''
               <form action='login' method='POST'>
                <input type='text' name='email' id='email' placeholder='email'></input>
                <input type='password' name='pw' id='pw' placeholder='password'></input>
                <input type='submit' name='submit'></input>
               </form>
               '''

    email = flask.request.form['email']
    if flask.request.form['pw'] == users[email]['pw']:
        user = User()
        user.id = email
        flask_login.login_user(user)
        return flask.redirect(flask.url_for('protected'))

    return 'Bad login'


@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.id
```

Finally we can define a view to clear the session and log users out:

```python
@app.route('/logout')
def logout():
    flask_login.logout_user()
    return 'Logged out'
```

We now have a basic working application that makes use of session-based
authentication. To round things off, we should provide a callback for login
failures:

```python
@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'
```

Complete documentation for Flask-Login is available on [ReadTheDocs](https://flask-login.readthedocs.io/en/latest/).


## Contributing

We welcome contributions! If you would like to hack on Flask-Login, please
follow these steps:

1. Fork this repository
2. Make your changes
3. Install the requirements in `dev-requirements.txt`
4. Submit a pull request after running `make check` (ensure it does not error!)

Please give us adequate time to review your submission. Thanks!
