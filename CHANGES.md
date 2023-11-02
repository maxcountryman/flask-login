Flask-Login Changelog
=====================

Version 0.7.0
-------------

Unreleased

- Bump to Python >= 3.8.
- Bump to Flask >= 2.3.0.
- Bump to Werkzeug >= 2.3.2.
- Remove previously deprecated code. #694
- Deprecate the `__about__` module and `__version__` attribute. Use `importlib.metadata`
  to get library information instead. #701
- Use modern `pyproject.toml` project metadata. Use flit_core instead of setuptools as
  build backend.
- Use `datetime.now(timezone.utc)` instead of deprecated `datetime.utcnow`. #758
- Never look at the `X-Forwarded-For` header, always use `request.remote_addr`,
  requiring the developer to configure `ProxyFix` appropriately. #700


Version 0.6.3
-------------

Released 2023-10-30

-   Compatibility with Flask 3 and Werkzeug 3. #813


Version 0.6.2
-------------

Released on July 25th, 2022

- Fix compatibility with Werkzeug 2.2 and Flask 2.2. #691
- Revert change to `expand_login_view` that attempted to preserve a
  dynamic subdomain value. Such values should be handled using
  `app.url_value_preprocessor` and `app.url_defaults`. #691
- Ensure deprecation warnings are present for deprecated features that
  will be removed in the next feature release.
  - Use `request_loader` instead of `header_loader`.
  - Use `user_loaded_from_request` instead of `user_loaded_from_header`.
  - Use `app.config["LOGIN_DISABLED"]` instead of `_login_disabled`.
  - Use `init_app` instead of `setup_app`.

Version 0.6.1
-------------

Released on May 1st, 2022

- Only preserve subdomain or host view args in unauthorized redirect #663
- The new utility function `login_remembered` returns `True` if the current
  login is remembered across sessions. #654
- Fix side effect potentially executing view twice for same request. #666
- Clarify usage of FlaskLoginClient test client in docs. #668

Version 0.6.0
-------------

Released on March 30th, 2022

- Drop support for Python 2.7, 3.5, and 3.6, which have all reached the
  end of their official support. #594, #638
- The minimum supported version of Flask is 1.0.4, and Werkzeug is
  1.0.1. However, projects are advised to use the latest versions of
  both. #639
- Only flash "needs_refresh_message" if value is set #464
- Modify `expand_login_view` to allow for subdomain and host matching for `login_view` #462
- Add accessors for `request_loader` and `user_loader` callback functions #472
- Change "remember_me" cookie to match Werkzeug default value #488
- Change "remember_me" cookie to `HttpOnly`, matching Flask session cookie #488
- Add example for using `unauthorized_handler` #492
- Fix `assertEqual` deprecation warning in pytest #518
- Fix `collections` deprecation warning under Python 3.8 #525
- Replace `safe_str_cmp` with `hmac.compare_digest` #585
- Document `REMEMBER_COOKIE_SAMESITE` config #577
- Revise setup.py to use README.md for long description #598
- Various documentation corrections #484, #482, #487, #534
- Fix `from flask_login import *` behavior, although note that
 `import *` is not usually a good pattern in code. #485
- `UserMixin.is_authenticated` will return whatever `is_active` returns
  by default. This prevents inactive users from logging in. #486, #530
- Session protection will only mark the session as not fresh if it's not
  already marked as such, avoiding modifying the session cookie
  unnecessarily. #612

Version 0.5.0
-------------

Released on February 9th, 2020

- New custom test client: `flask_login.FlaskLoginClient`.
  You can use this to write clearer automated tests. #431
- Prefix authenticated user_id, remember, and remember_seconds in Flask Session
  with underscores to prevent accidental usage in application code. #470
- Simplify user loading. #378
- Various documentation improvements. #393, #394, #397, #417
- Set session ID when setting next. #403
- Clear session identifier on logout. #404
- Ensure use of a safe and up-to-date version of Flask.
- Drop support of Python versions: 2.6, 3.3, 3.4 #450

Version 0.4.1
-------------

Released on December 2nd, 2017

- New config option USE_SESSION_FOR_NEXT to enable storing next url in session
  instead of url. #330
- Accept int seconds along with timedelta for REMEMBER_COOKIE_DURATION. #370
- New config option FORCE_HOST_FOR_REDIRECTS to force host for redirects. #371


Version 0.4.0
-------------

Released on October 26th, 2016

- Fixes OPTIONS exemption from login. #244
- Fixes use of MD5 by replacing with SHA512. #264
- BREAKING: The `login_manager.token_handler` function, `get_auth_token` method
  on the User class, and the `utils.make_secure_token` utility function have
  been removed to prevent users from creating insecure auth implementations.
  Use the `Alternative Tokens` example from the docs instead. #291


Version 0.3.2
-------------

Released on October 8th, 2015

- Fixes Python 2.6 compatibility.
- Updates SESSION_KEYS to include "remember".


Version 0.3.1
-------------

Released on September 30th, 2015

- Fixes removal of non-Flask-Login keys from session object when using 'strong'
  protection.


Version 0.3.0
-------------

Released on September 10th, 2015

- Fixes handling of X-Forward-For header.
- Update to use SHA512 instead of MD5 for session identifier creation.
- Fixes session creation for every view.
- BREAKING: UTC used to set cookie duration.
- BREAKING: Non-fresh logins now returns HTTP 401.
- Support unicode user IDs in cookie.
- Fixes user_logged_out signal invocation.
- Support for per-Blueprint login views.
- BREAKING: The `is_authenticated`, `is_active`, and `is_anonymous` members of
  the user class are now properties, not methods. Applications should update
  their user classes accordingly.
- Various other improvements including documentation and code clean up.


Version 0.2.11
--------------

Released on May 19th, 2014

- Fixes missing request loader invocation when authorization header exists.


Version 0.2.10
--------------

Released on March 9th, 2014

- Generalized `request_loader` introduced; ability to log users in via
  customized callback over request.
- Fixes request context dependency by explicitly checking `has_request_context`.
- Fixes remember me issues since lazy user loading changes.


Version 0.2.9
-------------

Released on December 28th, 2013

- Fixes anonymous user assignment.
- Fixes localization in Python 3.


Version 0.2.8
-------------

Released on December 21st 2013

- Support login via authorization header. This allows login via Basic Auth, for
  example. Useful in an API presentation context.
- Ability to override user ID method name. This is useful if the ID getter is
  named differently than the default.
- Session data is now only read when the user is requested. This can be
  beneficial for cookie and caching control when differenting between
  requests that use user information for rendering and ones where all users
  (including anonymous) get the same result (e.g. static pages)
- BREAKING: User *must* always be accessed through the ``current_user``
  local. This breaks any previous direct access to ``_request_ctx.top.user``.
  This is because user is not loaded until current_user is accessed.
- Fixes unnecessary access to the session when the user is anonymous
  and session protection is active.
  see https://github.com/maxcountryman/flask-login/issues/120
- Fixes issue where order dependency of applying the login manager
  before dependent applications was required.
  see https://github.com/mattupstate/flask-principal/issues/22
- Fixes Python 3 ``UserMixin`` hashing.
- Fixes incorrect documentation.


Previous Versions
=================

Prior to 0.2.8, no proper changelog was kept.
