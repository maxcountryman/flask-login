===========
Flask-Login
===========
.. currentmodule:: flask.ext.login

Flask-Login provides user session management for Flask. It handles the common
tasks of logging in, logging out, and remembering your users' sessions over
extended periods of time.

It will:

- Store the active user's ID in the session, and let you log them in and out
  easily.
- Let you restrict views to logged-in (or logged-out) users.
- Handle the normally-tricky "remember me" functionality.
- Help protect your users' sessions from being stolen by cookie thieves.
- Possibly integrate with Flask-Principal or other authorization extensions
  later on.

However, it does not:

- Impose a particular database or other storage method on you. You are
  entirely in charge of how the user is loaded.
- Restrict you to using usernames and passwords, OpenIDs, or any other method
  of authenticating.
- Handle permissions beyond "logged in or not."
- Handle user registration or account recovery.

.. contents::
   :local:
   :backlinks: none


Configuring your Application
============================
The most important part of an application that uses Flask-Login is the
`LoginManager` class. You should create one for your application somewhere in
your code, like this::

    login_manager = LoginManager()

The login manager contains the code that lets your application and Flask-Login
work together, such as how to load a user from an ID, where to send users when
they need to log in, and the like.

Once the actual application object has been created, you can configure it for
login with::

    login_manager.init_app(app)


How it Works
============
You will need to provide a `~LoginManager.user_loader` callback. This callback
is used to reload the user object from the user ID stored in the session. It
should take the `unicode` ID of a user, and return the corresponding user
object. For example::

    @login_manager.user_loader
    def load_user(userid):
        return User.get(userid)

It should return `None` (**not raise an exception**) if the ID is not valid.
(In that case, the ID will manually be removed from the session and processing
will continue.)

Once a user has authenticated, you log them in with the `login_user`
function. For example::

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            # login and validate the user...
            login_user(user)
            flash("Logged in successfully.")
            return redirect(request.args.get("next") or url_for("index"))
        return render_template("login.html", form=form)

It's that simple. You can then access the logged-in user with the
`current_user` proxy. Views that require your users to be logged in can be
decorated with the `login_required` decorator::

    @app.route("/settings")
    @login_required
    def settings():
        pass

When the user is ready to log out::

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(somewhere)

They will be logged out, and any cookies for their session will be cleaned up.


Your User Class
===============
The class that you use to represent users needs to implement these methods:

`is_authenticated()`
    Returns `True` if the user is authenticated, i.e. they have provided
    valid credentials. (Only authenticated users will fulfill the criteria
    of `login_required`.)

`is_active()`
    Returns `True` if this is an active user - in addition to being
    authenticated, they also have activated their account, not been suspended,
    or any condition your application has for rejecting an account. Inactive
    accounts may not log in (without being forced of course).

`is_anonymous()`
    Returns `True` if this is an anonymous user. (Actual users should return
    `False` instead.)

`get_id()`
    Returns a `unicode` that uniquely identifies this user, and can be used
    to load the user from the `~LoginManager.user_loader` callback. Note
    that this **must** be a `unicode` - if the ID is natively an `int` or some
    other type, you will need to convert it to `unicode`.

To make implementing a user class easier, you can inherit from `UserMixin`,
which provides default implementations for all of these methods. (It's not
required, though.)


Customizing the Login Process
=============================
By default, when a user attempts to access a `login_required` view without
being logged in, Flask-Login will flash a message and redirect them to the
log in view. (If the login view is not set, it will abort with a 401 error.)

The name of the log in view can be set as `LoginManager.login_view`.
For example::

    login_manager.login_view = "users.login"

The default message flashed is ``Please log in to access this page.`` To
customize the message, set `LoginManager.login_message`::

    login_manager.login_message = u"Bonvolu ensaluti por uzi tio paĝo."

To customize the message category, set `LoginManager.login_message_category`::

    login_manager.login_message_category = "info"

When the log in view is redirected to, it will have a ``next`` variable in the
query string, which is the page that the user was trying to access.

If you would like to customize the process further, decorate a function with
`LoginManager.unauthorized_handler`::

    @login_manager.unauthorized_handler
    def unauthorized():
        # do stuff
        return a_response


Anonymous Users
===============
By default, when a user is not actually logged in, `current_user` is set to
an `AnonymousUserMixin` object. It has the following properties:

- `is_active` and `is_authenticated` return `False`
- `is_anonymous` returns `True`
- `get_id` returns `None`

If you have custom requirements for anonymous users (for example, they need
to have a permissions field), you can provide a callable (either a class or
factory function) that creates anonymous users to the `LoginManager` with::

    login_manager.anonymous_user = MyAnonymousUser


Remember Me
===========
"Remember Me" functionality can be tricky to implement. However, Flask-Login
makes it nearly transparent - just pass ``remember=True`` to the `login_user`
call. A cookie will be saved on the user's computer, and then Flask-Login
will automatically restore the user ID from that cookie if it is not in the
session. The cookie is tamper-proof, so if the user tampers with it (i.e.
inserts someone else's user ID in place of their own), the cookie will merely
be rejected, as if it was not there.

That level of functionality is handled automatically. However, you can (and
should, if your application handles any kind of sensitive data) provide
additional infrastructure to increase the security of your remember cookies.


Alternative Tokens
------------------
Using the user ID as the value of the remember token is not necessarily
secure. More secure is a hash of the username and password combined, or
something similar. To add an alternative token, add a method to your user
objects:

`get_auth_token()`
    Returns an authentication token (as `unicode`) for the user. The auth
    token should uniquely identify the user, and preferably not be guessable
    by public information about the user such as their UID and name - nor
    should it expose such information.

Correspondingly, you should set a `~LoginManager.token_loader` function on the
`LoginManager`, which takes a token (as stored in the cookie) and returns the
appropriate `User` object.

The `make_secure_token` function is provided for creating auth tokens
conveniently. It will concatenate all of its arguments, then HMAC it with
the app's secret key to ensure maximum cryptographic security. (If you store
the user's token in the database permanently, then you may wish to add random
data to the token to further impede guessing.)

If your application uses passwords to authenticate users, including the
password (or the salted password hash you should be using) in the auth
token will ensure that if a user changes their password, their old
authentication tokens will cease to be valid.


Fresh Logins
------------
When a user logs in, their session is marked as "fresh," which indicates that
they actually authenticated on that session. When their session is destroyed
and they are logged back in with a "remember me" cookie, it is marked as
"non-fresh." `login_required` does not differentiate between freshness, which
is fine for most pages. However, sensitive actions like changing one's
personal information should require a fresh login. (Actions like changing
one's password should always require a password re-entry regardless.)

`fresh_login_required`, in addition to verifying that the user is logged
in, will also ensure that their login is fresh. If not, it will send them to
a page where they can re-enter their credentials. You can customize its
behavior in the same ways as you can customize `login_required`, by setting
`LoginManager.refresh_view`, `~LoginManager.needs_refresh_message`, and
`~LoginManager.needs_refresh_message_category`::

    login_manager.refresh_view = "accounts.reauthenticate"
    login_manager.needs_refresh_message = (
        u"To protect your account, please reauthenticate to access this page."
    )
    login_manager.needs_refresh_message_category = "info"

Or by providing your own callback to handle refreshing::

    @login_manager.needs_refresh_handler
    def refresh():
        # do stuff
        return a_response

To mark a session as fresh again, call the `confirm_login` function.


Cookie Settings
---------------
The details of the cookie can be customized in the application settings.

=========================== =================================================
`REMEMBER_COOKIE_NAME`      The name of the cookie to store the "remember me"
                            information in. **Default:** ``remember_token``
`REMEMBER_COOKIE_DURATION`  The amount of time before the cookie expires, as
                            a `datetime.timedelta` object.
                            **Default:** 365 days (1 non-leap Gregorian year)
`REMEMBER_COOKIE_DOMAIN`    If the "Remember Me" cookie should cross domains,
                            set the domain value here (i.e. ``.example.com``
                            would allow the cookie to be used on all
                            subdomains of ``example.com``).
                            **Default:** `None`
=========================== =================================================


Session Protection
==================
While the features above help secure your "Remember Me" token from cookie
thieves, the session cookie is still vulnerable. Flask-Login includes session
protection to help prevent your users' sessions from being stolen.

You can configure session protection on the `LoginManager`, and in the app's
configuration. If it is enabled, it can operate in either `basic` or `strong`
mode. To set it on the `LoginManager`, set the
`~LoginManager.session_protection` attribute to ``"basic"`` or ``"strong"``::

    login_manager.session_protection = "strong"

Or, to disable it::

    login_manager.session_protection = None

By default, it is activated in ``"basic"`` mode. It can be disabled in the
app's configuration by setting the `SESSION_PROTECTION` setting to `None`,
``"basic"``, or ``"strong"``.

When session protection is active, each request, it generates an identifier
for the user's computer (basically, the MD5 hash of the IP address and user
agent). If the session does not have an associated identifier, the one
generated will be stored. If it has an identifier, and it matches the one
generated, then the request is OK.

If the identifiers do not match in `basic` mode, or when the session is
permanent, then the session will simply be marked as non-fresh, and anything
requiring a fresh login will force the user to re-authenticate. (Of course,
you must be already using fresh logins where appropriate for this to have an
effect.)

If the identifiers do not match in `strong` mode for a non-permanent session,
then the entire session (as well as the remember token if it exists) is
deleted.


API Documentation
=================
This documentation is automatically generated from Flask-Login's source code.


Configuring Login
-----------------
.. autoclass:: LoginManager
   
   .. automethod:: setup_app
   
   .. automethod:: unauthorized
   
   .. automethod:: needs_refresh
   
   .. rubric:: General Configuration
   
   .. automethod:: user_loader
   
   .. automethod:: token_loader
   
   .. attribute:: anonymous_user
   
      A class or factory function that produces an anonymous user, which
      is used when no one is logged in.
   
   .. rubric:: `unauthorized` Configuration
   
   .. attribute:: login_view
   
      The name of the view to redirect to when the user needs to log in. (This
      can be an absolute URL as well, if your authentication machinery is
      external to your application.)
   
   .. attribute:: login_message
   
      The message to flash when a user is redirected to the login page.
   
   .. automethod:: unauthorized_handler
   
   .. rubric:: `needs_refresh` Configuration
   
   .. attribute:: refresh_view
   
      The name of the view to redirect to when the user needs to
      reauthenticate.
   
   .. attribute:: needs_refresh_message
   
      The message to flash when a user is redirected to the reauthentication
      page.
   
   .. automethod:: needs_refresh_handler


Login Mechanisms
----------------
.. data:: current_user

   A proxy for the current user.

.. autofunction:: login_fresh

.. autofunction:: login_user

.. autofunction:: logout_user

.. autofunction:: confirm_login


Protecting Views
----------------
.. autofunction:: login_required

.. autofunction:: fresh_login_required


User Object Helpers
-------------------
.. autoclass:: UserMixin
   :members:

.. autoclass:: AnonymousUser
   :members:


Utilities
---------
.. autofunction:: login_url

.. autofunction:: make_secure_token


Signals
-------
See the `Flask documentation on signals`_ for information on how to use these
signals in your code.

.. data:: user_logged_in

   Sent when a user is logged in. In addition to the app (which is the
   sender), it is passed `user`, which is the user being logged in.

.. data:: user_logged_out

   Sent when a user is logged out. In addition to the app (which is the
   sender), it is passed `user`, which is the user being logged out.

.. data:: user_login_confirmed

   Sent when a user's login is confirmed, marking it as fresh. (It is not
   called for a normal login.)
   It receives no additional arguments besides the app.

.. data:: user_unauthorized

   Sent when the `unauthorized` method is called on a `LoginManager`. It
   receives no additional arguments besides the app.

.. data:: user_needs_refresh

   Sent when the `needs_refresh` method is called on a `LoginManager`. It
   receives no additional arguments besides the app.

.. data:: session_protected

   Sent whenever session protection takes effect, and a session is either
   marked non-fresh or deleted. It receives no additional arguments besides
   the app.

.. _Flask documentation on signals: http://flask.pocoo.org/docs/signals/
