===========
Flask-Login
===========
.. currentmodule:: flask_login

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
    def load_user(user_id):
        return User.get(user_id)

It should return `None` (**not raise an exception**) if the ID is not valid.
(In that case, the ID will manually be removed from the session and processing
will continue.)

Your User Class
===============
The class that you use to represent users needs to implement these properties
and methods:

`is_authenticated`
    This property should return `True` if the user is authenticated, i.e. they
    have provided valid credentials. (Only authenticated users will fulfill
    the criteria of `login_required`.)

`is_active`
    This property should return `True` if this is an active user - in addition
    to being authenticated, they also have activated their account, not been
    suspended, or any condition your application has for rejecting an account.
    Inactive accounts may not log in (without being forced of course).

`is_anonymous`
    This property should return `True` if this is an anonymous user. (Actual
    users should return `False` instead.)

`get_id()`
    This method must return a `unicode` that uniquely identifies this user,
    and can be used to load the user from the `~LoginManager.user_loader`
    callback. Note that this **must** be a `unicode` - if the ID is natively
    an `int` or some other type, you will need to convert it to `unicode`.

To make implementing a user class easier, you can inherit from `UserMixin`,
which provides default implementations for all of these properties and methods.
(It's not required, though.)

Login Example
=============

Once a user has authenticated, you log them in with the `login_user`
function.

    For example:

.. code-block:: python
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Here we use a class of some kind to represent and validate our
        # client-side form data. For example, WTForms is a library that will
        # handle this for us, and we use a custom LoginForm to validate.
        form = LoginForm()
        if form.validate_on_submit():
            # Login and validate the user.
            # user should be an instance of your `User` class
            login_user(user)

            flask.flash('Logged in successfully.')

            next = flask.request.form['next']
            # next_is_valid should check if the user has valid 
            # permission to access the `next` url
            if not next_is_valid(next):
                return flask.abort(400)

            return flask.redirect(next or flask.url_for('index'))
        return flask.render_template('login.html', next=flask.request.args.get('next'), form=form)

*Warning:* You MUST validate the value of the `next` parameter. If you do not,
your application will be vulnerable to open redirects.

It's that simple. You can then access the logged-in user with the
`current_user` proxy, which is available in every template::

    {% if current_user.is_authenticated %}
      Hi {{ current_user.name }}!
    {% endif %}

Views that require your users to be logged in can be
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

    login_manager.login_message = u"Bonvolu ensaluti por uzi tiun paĝon."

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


Login using Authorization header
================================

.. Caution::
   This method will be deprecated; use the `~LoginManager.request_loader`
   below instead.

Sometimes you want to support Basic Auth login using the `Authorization`
header, such as for api requests. To support login via header you will need
to provide a `~LoginManager.header_loader` callback. This callback should behave
the same as your `~LoginManager.user_loader` callback, except that it accepts
a header value instead of a user id. For example::

    @login_manager.header_loader
    def load_user_from_header(header_val):
        header_val = header_val.replace('Basic ', '', 1)                                
        try:                                                                        
            header_val = base64.b64decode(header_val)                                       
        except TypeError:                                                     
            pass
        return User.query.filter_by(api_key=header_val).first()
        
By default the `Authorization` header's value is passed to your
`~LoginManager.header_loader` callback. You can change the header used with
the `AUTH_HEADER_NAME` configuration.


Custom Login using Request Loader
=================================
Sometimes you want to login users without using cookies, such as using header
values or an api key passed as a query argument. In these cases, you should use
the `~LoginManager.request_loader` callback. This callback should behave the
same as your `~LoginManager.user_loader` callback, except that it accepts the
Flask request instead of a user_id.

For example, to support login from both a url argument and from Basic Auth
using the `Authorization` header::

    @login_manager.request_loader
    def load_user_from_request(request):

        # first, try to login using the api_key url arg
        api_key = request.args.get('api_key')
        if api_key:
            user = User.query.filter_by(api_key=api_key).first()
            if user:
                return user

        # next, try to login using Basic Auth
        api_key = request.headers.get('Authorization')
        if api_key:
            api_key = api_key.replace('Basic ', '', 1)                                
            try:                                                                        
                api_key = base64.b64decode(api_key)                                       
            except TypeError:                                                     
                pass
            user = User.query.filter_by(api_key=api_key).first()
            if user:
                return user

        # finally, return None if both methods did not login the user
        return None
        

Anonymous Users
===============
By default, when a user is not actually logged in, `current_user` is set to
an `AnonymousUserMixin` object. It has the following properties and methods:

- `is_active` and `is_authenticated` are `False`
- `is_anonymous` is `True`
- `get_id()` returns `None`

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
Using the user ID as the value of the remember token means you must change the
user's ID to invalidate their login sessions. One way to improve this is to use
an alternative session token instead of the user's ID. For example::

    @login_manager.user_loader
    def load_user(session_token):
        return User.query.filter_by(session_token=session_token).first()

Then the `~UserMixin.get_id` method of your User class would return the session
token instead of the user's ID::

    def get_id(self):
        return unicode(self.session_token)

This way you are free to change the user's session token to a new randomly
generated value when the user changes their password, which would ensure their
old authentication sessions will cease to be valid. Note that the session
token must still uniquely identify the user... think of it as a second user ID.


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
`REMEMBER_COOKIE_PATH`      Limits the "Remember Me" cookie to a certain path.
                            **Default:** ``/``
`REMEMBER_COOKIE_SECURE`    Restricts the "Remember Me" cookie's scope to
                            secure channels (typically HTTPS).
                            **Default:** `None`
`REMEMBER_COOKIE_HTTPONLY`  Prevents the "Remember Me" cookie from being
                            accessed by client-side scripts.
                            **Default:** `False`
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
for the user's computer (basically, a secure hash of the IP address and user
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


Localization
============
By default, the `LoginManager` uses ``flash`` to display messages when a user
is required to log in. These messages are in English. If you require
localization, set the `localize_callback` attribute of `LoginManager` to a
function to be called with these messages before they're sent to ``flash``,
e.g. ``gettext``. This function will be called with the message and its return
value will be sent to ``flash`` instead.


API Documentation
=================
This documentation is automatically generated from Flask-Login's source code.


Configuring Login
-----------------

.. module:: flask_login

.. autoclass:: LoginManager
   
   .. automethod:: setup_app
   
   .. automethod:: unauthorized
   
   .. automethod:: needs_refresh
   
   .. rubric:: General Configuration
   
   .. automethod:: user_loader
   
   .. automethod:: header_loader
   
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

.. autoclass:: AnonymousUserMixin
   :members:


Utilities
---------
.. autofunction:: login_url


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
