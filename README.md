# Flask-Login

Flask-Login provides user session management for [Flask][]. It handles the common
tasks of logging in, logging out, and remembering your users' sessions over
extended periods of time.

Flask-Login is not bound to any particular database system or permissions
model. The only requirement is that your user objects implement a few methods,
and that you provide a callback to the extension capable of loading users from
their ID.

Read the documentation at <https://flask-login.readthedocs.io>.

[Flask]: https://flask.palletsprojects.com


## A Basic Example

Let's walk through setting up a basic application. Note that this is a very basic guide:
we will be taking shortcuts here that you should never take in a real application.

To begin we'll set up a Flask app and a `LoginManager` from Flask-Login.

```python
import flask
import flask_login

app = flask.Flask(__name__)
app.secret_key = "super secret string"  # Change this!

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
```

To keep things simple we're going to use a basic `User` class and a dictionary to
represent a database of users. In a real application, this would be an actual
persistence layer. However, it's important to point out this is a feature of
Flask-Login: it doesn't care how your data is stored so long as you tell it how to
retrieve it!

```python
class User(flask_login.UserMixin):
    def __init__(self, email, password):
        self.id = email
        self.password = password

users = {"leafstorm": User("leafstorm", "secret")}
```

We also need to tell the login manager how to load a user from a request by defining its
`user_loader` callback. If no user is found it returns `None`.

```python
@login_manager.user_loader
def user_loader(id):
    return users.get(id)
```

Now we're ready to define our views. The login view will populate the session with
authentication info. The protected view will only be avialble to authenticated users;
visiting it otherwise will show an error. The logout view clearing the session.

```python
@app.get("/login")
def login():
    return """<form method=post>
      Email: <input name="email"><br>
      Password: <input name="password" type=password><br>
      <button>Log In</button>
    </form>"""

@app.post("/login")
def login():
    user = users.get(flask.request.form["email"])

    if user is None or user.password != flask.request.form["password"]:
        return flask.redirect(flask.url_for("login"))

    flask_login.login_user(user)
    return flask.redirect(flask.url_for("protected"))

@app.route("/protected")
@flask_login.login_required
def protected():
    return flask.render_template_string(
        "Logged in as: {{ user.id }}",
        user=flask_login.current_user
    )

@app.route("/logout")
def logout():
    flask_login.logout_user()
    return "Logged out"
```
