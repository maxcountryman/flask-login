# -*- coding: utf-8 -*-
'''
    flask.ext.login.config
    ----------------------
    This module provides default configuration values.
'''


from datetime import timedelta


#: The default name of the "remember me" cookie (``remember_token``)
COOKIE_NAME = 'remember_token'


#: The default time before the "remember me" cookie expires (365 days).
COOKIE_DURATION = timedelta(days=365)


#: Whether the "remember me" cookie requires Secure; defaults to ``None``
COOKIE_SECURE = None


#: Whether the "remember me" cookie uses HttpOnly or not; defaults to ``False``
COOKIE_HTTPONLY = False


#: The default flash message to display when users need to log in.
LOGIN_MESSAGE = u'Please log in to access this page.'


#: The default flash message category to display when users need to log in.
LOGIN_MESSAGE_CATEGORY = 'message'


#: The default flash message to display when users need to reauthenticate.
REFRESH_MESSAGE = u'Please reauthenticate to access this page.'


#: The default flash message category to display when users need to
#: reauthenticate.
REFRESH_MESSAGE_CATEGORY = 'message'


#: The default attribute to retreive the unicode id of the user
ID_ATTRIBUTE = 'get_id'


#: Default name of the auth header (``Authorization``)
AUTH_HEADER_NAME = 'Authorization'
