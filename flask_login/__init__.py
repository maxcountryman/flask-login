# -*- coding: utf-8 -*-
'''
    flask.ext.login
    ---------------
    This module provides user session management for Flask. It lets you log
    your users in and out in a database-independent manner.
    :copyright: (c) 2011 by Matthew Frazier.
    :license: MIT/X11, see LICENSE for more details.
'''


__all__ = ['LoginManager']


from .config import (COOKIE_NAME, COOKIE_DURATION, COOKIE_SECURE,
                     COOKIE_HTTPONLY, LOGIN_MESSAGE, LOGIN_MESSAGE_CATEGORY,
                     REFRESH_MESSAGE, REFRESH_MESSAGE_CATEGORY, ID_ATTRIBUTE,
                     AUTH_HEADER_NAME)
from .login_manager import LoginManager
from .mixin import UserMixin, AnonymousUserMixin
from .signals import (user_logged_in, user_logged_out, user_loaded_from_cookie,
                      user_loaded_from_header, user_loaded_from_request,
                      user_login_confirmed, user_unauthorized,
                      user_needs_refresh, user_accessed, session_protected)
from .utils import (current_user, login_url, make_secure_token,
                    login_fresh, login_user, logout_user, confirm_login,
                    login_required, fresh_login_required, set_login_view,
                    encode_cookie, decode_cookie, make_next_param)


# prevent pyflakes from failing from unused imports
assert (COOKIE_NAME, COOKIE_DURATION, COOKIE_SECURE, COOKIE_HTTPONLY,
        LOGIN_MESSAGE, LOGIN_MESSAGE_CATEGORY, REFRESH_MESSAGE,
        REFRESH_MESSAGE_CATEGORY, ID_ATTRIBUTE, AUTH_HEADER_NAME)
assert (LoginManager, UserMixin, AnonymousUserMixin)
assert (user_logged_in, user_logged_out, user_loaded_from_cookie,
        user_loaded_from_header, user_loaded_from_request,
        user_login_confirmed, user_unauthorized, user_needs_refresh,
        user_accessed, session_protected)
assert (current_user, login_url, make_secure_token, login_fresh, login_user,
        logout_user, confirm_login, login_required, fresh_login_required,
        set_login_view, encode_cookie, decode_cookie, make_next_param)
