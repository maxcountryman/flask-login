# -*- coding: utf-8 -*-
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from datetime import timedelta, datetime
from contextlib import contextmanager


from werkzeug import __version__ as werkzeug_version
from flask import Flask, Response, session, get_flashed_messages

from flask.ext.login import (LoginManager, UserMixin, AnonymousUserMixin,
                             make_secure_token, current_user, login_user,
                             logout_user, user_logged_in, user_logged_out,
                             user_loaded_from_cookie, user_login_confirmed,
                             user_unauthorized, user_needs_refresh,
                             make_next_param, login_url, login_fresh,
                             login_required, session_protected,
                             fresh_login_required, confirm_login,
                             encode_cookie, decode_cookie,
                             _user_context_processor)


# be compatible with py3k
if str is not bytes:
    unicode = str


@contextmanager
def listen_to(signal):
    ''' Context Manager that listens to signals and records emissions

    Example:

    with listen_to(user_logged_in) as listener:
        login_user(user)

        # Assert that a single emittance of the specific args was seen.
        listener.assert_heard_one(app, user=user))

        # Of course, you can always just look at the list yourself
        self.assertEqual(1, len(listener.heard))

    '''
    class _SignalsCaught(object):
        def __init__(self):
            self.heard = []

        def add(self, *args, **kwargs):
            ''' The actual handler of the signal. '''
            self.heard.append((args, kwargs))

        def assert_heard_one(self, *args, **kwargs):
            ''' The signal fired once, and with the arguments given '''
            if len(self.heard) == 0:
                raise AssertionError('No signals were fired')
            elif len(self.heard) > 1:
                msg = '{0} signals were fired'.format(len(self.heard))
                raise AssertionError(msg)
            elif self.heard[0] != (args, kwargs):
                msg = 'One signal was heard, but with incorrect arguments: '\
                    '({0}, {1})'
                raise AssertionError(msg.format(args, kwargs))

    results = _SignalsCaught()
    signal.connect(results.add)

    try:
        yield results
    finally:
        signal.disconnect(results.add)


class User(UserMixin):
    def __init__(self, name, id, active=True):
        self.id = id
        self.name = name
        self.active = active

    def get_id(self):
        return self.id

    def is_active(self):
        return self.active

    def get_auth_token(self):
        return make_secure_token(self.name, key='deterministic')


notch = User(u'Notch', 1)
steve = User(u'Steve', 2)
creeper = User(u'Creeper', 3, False)

USERS = {1: notch, 2: steve, 3: creeper}
USER_TOKENS = dict((u.get_auth_token(), u) for u in USERS.values())


class StaticTestCase(unittest.TestCase):
    def test_static_loads_anonymous(self):
        app = Flask(__name__)
        app.static_url_path = '/static'
        lm = LoginManager()
        lm.init_app(app)

        with app.test_client() as c:
            c.get('/static/favicon.ico')
            self.assertTrue(current_user.is_anonymous())


class InitializationTestCase(unittest.TestCase):
    ''' Tests the two initialization methods '''

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True

    def test_init_app(self):
        login_manager = LoginManager()
        login_manager.init_app(self.app, add_context_processor=True)

        self.assertIsInstance(login_manager, LoginManager)

    def test_class_init(self):
        login_manager = LoginManager(self.app, add_context_processor=True)

        self.assertIsInstance(login_manager, LoginManager)


class LoginTestCase(unittest.TestCase):
    ''' Tests for results of the login_user function '''

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'deterministic'
        self.app.config['SESSION_PROTECTION'] = None
        self.app.config['TESTING'] = True
        self.remember_cookie_name = 'remember'
        self.app.config['REMEMBER_COOKIE_NAME'] = self.remember_cookie_name
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        @self.app.route('/')
        def index():
            return u'Welcome!'

        @self.app.route('/secret')
        def secret():
            return self.login_manager.unauthorized()

        @self.app.route('/login-notch')
        def login_notch():
            return unicode(login_user(notch))

        @self.app.route('/login-notch-remember')
        def login_notch_remember():
            return unicode(login_user(notch, remember=True))

        @self.app.route('/login-notch-permanent')
        def login_notch_permanent():
            session.permanent = True
            return unicode(login_user(notch))

        @self.app.route('/needs-refresh')
        def needs_refresh():
            return self.login_manager.needs_refresh()

        @self.app.route('/confirm-login')
        def _confirm_login():
            confirm_login()
            return u''

        @self.app.route('/username')
        def username():
            if current_user.is_authenticated():
                return current_user.name
            return u'Anonymous'

        @self.app.route('/is-fresh')
        def is_fresh():
            return unicode(login_fresh())

        @self.app.route('/logout')
        def logout():
            return unicode(logout_user())

        @self.login_manager.user_loader
        def load_user(user_id):
            return USERS[int(user_id)]

        @self.app.route('/empty_session')
        def empty_session():
            return unicode(u'modified=%s' % session.modified)

        # This will help us with the possibility of typoes in the tests. Now
        # we shouldn't have to check each response to help us set up state
        # (such as login pages) to make sure it worked: we will always
        # get an exception raised (rather than return a 404 response)
        @self.app.errorhandler(404)
        def handle_404(e):
            raise e

        unittest.TestCase.setUp(self)

    def _get_remember_cookie(self, test_client):
        our_cookies = test_client.cookie_jar._cookies['localhost.local']['/']
        return our_cookies[self.remember_cookie_name]

    def _delete_session(self, c):
        # Helper method to cause the session to be deleted
        # as if the browser was closed. This will remove
        # the session regardless of the permament flag
        # on the session!
        with c.session_transaction() as sess:
            sess.clear()

    #
    # Login
    #
    def test_test_request_context_users_are_anonymous(self):
        with self.app.test_request_context():
            self.assertTrue(current_user.is_anonymous())

    def test_defaults_anonymous(self):
        with self.app.test_client() as c:
            result = c.get('/username')
            self.assertEqual(u'Anonymous', result.data.decode('utf-8'))

    def test_login_user(self):
        with self.app.test_request_context():
            result = login_user(notch)
            self.assertTrue(result)
            self.assertEqual(current_user.name, u'Notch')

    def test_login_user_emits_signal(self):
        with self.app.test_request_context():
            with listen_to(user_logged_in) as listener:
                login_user(notch)
                listener.assert_heard_one(self.app, user=notch)

    def test_login_inactive_user(self):
        with self.app.test_request_context():
            result = login_user(creeper)
            self.assertTrue(current_user.is_anonymous())
            self.assertFalse(result)

    def test_login_inactive_user_forced(self):
        with self.app.test_request_context():
            login_user(creeper, force=True)
            self.assertEqual(current_user.name, u'Creeper')

    #
    # Logout
    #
    def test_logout_logs_out_current_user(self):
        with self.app.test_request_context():
            login_user(notch)
            logout_user()
            self.assertTrue(current_user.is_anonymous())

    def test_logout_emits_signal(self):
        with self.app.test_request_context():
            login_user(notch)
            with listen_to(user_logged_out) as listener:
                logout_user()
                listener.assert_heard_one(self.app, user=notch)

    #
    # Unauthorized
    #
    def test_unauthorized_fires_unauthorized_signal(self):
        with self.app.test_client() as c:
            with listen_to(user_unauthorized) as listener:
                c.get('/secret')
                listener.assert_heard_one(self.app)

    def test_unauthorized_flashes_message_with_login_view(self):
        self.login_manager.login_view = '/login'

        expected_message = self.login_manager.login_message = u'Log in!'
        expected_category = self.login_manager.login_message_category = 'login'

        with self.app.test_client() as c:
            c.get('/secret')
            msgs = get_flashed_messages(category_filter=[expected_category])
            self.assertEqual([expected_message], msgs)

    def test_unauthorized_uses_authorized_handler(self):
        @self.login_manager.unauthorized_handler
        def _callback():
            return Response('This is secret!', 401)

        with self.app.test_client() as c:
            result = c.get('/secret')
            self.assertEqual(result.status_code, 401)
            self.assertEqual(u'This is secret!', result.data.decode('utf-8'))

    def test_unauthorized_aborts_with_401(self):
        with self.app.test_client() as c:
            result = c.get('/secret')
            self.assertEqual(result.status_code, 401)

    def test_unauthorized_redirects_to_login_view(self):
        self.login_manager.login_view = 'login'

        @self.app.route('/login')
        def login():
            return 'Login Form Goes Here!'

        with self.app.test_client() as c:
            result = c.get('/secret')
            self.assertEqual(result.status_code, 302)
            self.assertEqual(result.location,
                             'http://localhost/login?next=%2Fsecret')

    #
    # Session Persistence/Freshness
    #
    def test_login_persists(self):
        with self.app.test_client() as c:
            c.get('/login-notch')
            result = c.get('/username')

            self.assertEqual(u'Notch', result.data.decode('utf-8'))

    def test_logout_persists(self):
        with self.app.test_client() as c:
            c.get('/login-notch')
            c.get('/logout')
            result = c.get('/username')
            self.assertEqual(result.data.decode('utf-8'), u'Anonymous')

    def test_incorrect_id_logs_out(self):
        # Ensure that any attempt to reload the user by the ID
        # will seem as if the user is no longer valid
        @self.login_manager.user_loader
        def new_user_loader(user_id):
            return

        with self.app.test_client() as c:
            # Successfully logs in
            c.get('/login-notch')
            result = c.get('/username')

            self.assertEqual(u'Anonymous', result.data.decode('utf-8'))

    def test_authentication_is_fresh(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/is-fresh')
            self.assertEqual(u'True', result.data.decode('utf-8'))

    def test_remember_me(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            result = c.get('/username')
            self.assertEqual(u'Notch', result.data.decode('utf-8'))

    def test_remember_me_uses_custom_cookie_parameters(self):
        name = self.app.config['REMEMBER_COOKIE_NAME'] = 'myname'
        duration = self.app.config['REMEMBER_COOKIE_DURATION'] = \
            timedelta(days=2)
        domain = self.app.config['REMEMBER_COOKIE_DOMAIN'] = '.localhost.local'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')

            # TODO: Is there a better way to test this?
            self.assertTrue(domain in c.cookie_jar._cookies,
                            'Custom domain not found as cookie domain')
            domain_cookie = c.cookie_jar._cookies[domain]
            self.assertTrue(name in domain_cookie['/'],
                            'Custom name not found as cookie name')
            cookie = domain_cookie['/'][name]

            expiration_date = datetime.fromtimestamp(cookie.expires)
            expected_date = datetime.now() + duration
            difference = expected_date - expiration_date

            fail_msg = 'The expiration date {0} was far from the expected {1}'
            fail_msg = fail_msg.format(expiration_date, expected_date)
            self.assertLess(difference, timedelta(seconds=10), fail_msg)
            self.assertGreater(difference, timedelta(seconds=-10), fail_msg)

    def test_remember_me_is_unfresh(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            self.assertEqual(u'False', c.get('/is-fresh').data.decode('utf-8'))

    def test_user_loaded_from_cookie_fired(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            with listen_to(user_loaded_from_cookie) as listener:
                c.get('/username')
                listener.assert_heard_one(self.app, user=notch)

    def test_logout_stays_logged_out_with_remember_me(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            c.get('/logout')
            result = c.get('/username')
            self.assertEqual(result.data.decode('utf-8'), u'Anonymous')

    def test_needs_refresh_uses_handler(self):
        @self.login_manager.needs_refresh_handler
        def _on_refresh():
            return u'Needs Refresh!'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/needs-refresh')
            self.assertEqual(u'Needs Refresh!', result.data.decode('utf-8'))

    def test_needs_refresh_fires_needs_refresh_signal(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            with listen_to(user_needs_refresh) as listener:
                c.get('/needs-refresh')
                listener.assert_heard_one(self.app)

    def test_needs_refresh_fires_flash_when_redirect_to_refresh_view(self):
        self.login_manager.refresh_view = '/refresh_view'

        self.login_manager.needs_refresh_message = u'Refresh'
        self.login_manager.needs_refresh_message_category = 'refresh'
        category_filter = [self.login_manager.needs_refresh_message_category]

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            c.get('/needs-refresh')
            msgs = get_flashed_messages(category_filter=category_filter)
            self.assertIn(self.login_manager.needs_refresh_message, msgs)

    def test_needs_refresh_aborts_403(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/needs-refresh')
            self.assertEqual(result.status_code, 403)

    def test_redirects_to_refresh_view(self):
        @self.app.route('/refresh-view')
        def refresh_view():
            return ''

        self.login_manager.refresh_view = 'refresh_view'
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/needs-refresh')
            self.assertEqual(result.status_code, 302)
            expected = 'http://localhost/refresh-view?next=%2Fneeds-refresh'
            self.assertEqual(result.location, expected)

    def test_confirm_login(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            self.assertEqual(u'False', c.get('/is-fresh').data.decode('utf-8'))
            c.get('/confirm-login')
            self.assertEqual(u'True', c.get('/is-fresh').data.decode('utf-8'))

    def test_user_login_confirmed_signal_fired(self):
        with self.app.test_client() as c:
            with listen_to(user_login_confirmed) as listener:
                c.get('/confirm-login')
                listener.assert_heard_one(self.app)

    def test_session_not_modified(self):
        with self.app.test_client() as c:
            # Within the request we think we didn't modify the session.
            self.assertEquals(
                u'modified=False',
                c.get('/empty_session').data.decode('utf-8'))
            # But after the request, the session could be modified by the
            # "after_request" handlers that call _update_remember_cookie.
            # Ensure that if nothing changed the session is not modified.
            self.assertFalse(session.modified)

    #
    # Session Protection
    #
    def test_session_protection_basic_marks_session_unfresh(self):
        self.app.config['SESSION_PROTECTION'] = 'basic'
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            username_result = c.get('/username',
                                    headers=[('User-Agent', 'different')])
            self.assertEqual(u'Notch', username_result.data.decode('utf-8'))
            fresh_result = c.get('/is-fresh')
            self.assertEqual(u'False', fresh_result.data.decode('utf-8'))

    def test_session_protection_basic_fires_signal(self):
        self.app.config['SESSION_PROTECTION'] = 'basic'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            with listen_to(session_protected) as listener:
                c.get('/username', headers=[('User-Agent', 'different')])
                listener.assert_heard_one(self.app)

    def test_permanent_strong_session_protection_marks_session_unfresh(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'
        with self.app.test_client() as c:
            c.get('/login-notch-permanent')
            username_result = c.get('/username', headers=[('User-Agent',
                                                           'different')])
            self.assertEqual(u'Notch', username_result.data.decode('utf-8'))
            fresh_result = c.get('/is-fresh')
            self.assertEqual(u'False', fresh_result.data.decode('utf-8'))

    def test_permanent_strong_session_protection_fires_signal(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'

        with self.app.test_client() as c:
            c.get('/login-notch-permanent')
            with listen_to(session_protected) as listener:
                c.get('/username', headers=[('User-Agent', 'different')])
                listener.assert_heard_one(self.app)

    def test_session_protection_strong_deletes_session(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            username_result = c.get('/username', headers=[('User-Agent',
                                                           'different')])
            self.assertEqual(u'Anonymous',
                             username_result.data.decode('utf-8'))

    def test_session_protection_strong_fires_signal_user_agent(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            with listen_to(session_protected) as listener:
                c.get('/username', headers=[('User-Agent', 'different')])
                listener.assert_heard_one(self.app)

    def test_session_protection_strong_fires_signal_x_forwarded_for(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'

        with self.app.test_client() as c:
            c.get('/login-notch-remember',
                  headers=[('X-Forwarded-For', '10.1.1.1')])
            with listen_to(session_protected) as listener:
                c.get('/username', headers=[('X-Forwarded-For', '10.1.1.2')])
                listener.assert_heard_one(self.app)

    #
    # Custom Token Loader
    #
    def test_custom_token_loader(self):
        @self.login_manager.token_loader
        def load_token(token):
            return USER_TOKENS.get(token)

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)

            # Test that remember me functionality still works
            self.assertEqual(u'Notch', c.get('/username').data.decode('utf-8'))

            # Test that we used the custom authentication token
            remember_cookie = self._get_remember_cookie(c)
            expected_value = make_secure_token(u'Notch', key='deterministic')
            self.assertEqual(expected_value, remember_cookie.value)

    def test_change_api_key_with_token_loader(self):
        @self.login_manager.token_loader
        def load_token(token):
            return USER_TOKENS.get(token)

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            self.app.config['SECRET_KEY'] = 'ima change this now'

            result = c.get('/username')
            self.assertEqual(result.data.decode('utf-8'), u'Notch')

    def test_custom_token_loader_with_no_user(self):
        @self.login_manager.token_loader
        def load_token(token):
            return

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)

            result = c.get('/username')
            self.assertEqual(result.data.decode('utf-8'), u'Anonymous')

    #
    # View Decorators
    #
    def test_login_required_decorator(self):
        @self.app.route('/protected')
        @login_required
        def protected():
            return u'Access Granted'

        with self.app.test_client() as c:
            result = c.get('/protected')
            self.assertEqual(result.status_code, 401)

            c.get('/login-notch')
            result2 = c.get('/protected')
            self.assertIn(u'Access Granted', result2.data.decode('utf-8'))

    def test_fresh_login_required_decorator(self):
        @self.app.route('/very-protected')
        @fresh_login_required
        def very_protected():
            return 'Access Granted'

        with self.app.test_client() as c:
            result = c.get('/very-protected')
            self.assertEqual(result.status_code, 401)

            c.get('/login-notch-remember')
            logged_in_result = c.get('/very-protected')
            self.assertEqual(u'Access Granted',
                             logged_in_result.data.decode('utf-8'))

            self._delete_session(c)
            stale_result = c.get('/very-protected')
            self.assertEqual(stale_result.status_code, 403)

            c.get('/confirm-login')
            refreshed_result = c.get('/very-protected')
            self.assertEqual(u'Access Granted',
                             refreshed_result.data.decode('utf-8'))

    #
    # Misc
    #
    @unittest.skipIf(werkzeug_version.startswith("0.9"),
                     "wait for upstream implementing RFC 5987")
    def test_chinese_user_agent(self):
        with self.app.test_client() as c:
            result = c.get('/', headers=[('User-Agent', u'中文')])
            self.assertEqual(u'Welcome!', result.data.decode('utf-8'))

    @unittest.skipIf(werkzeug_version.startswith("0.9"),
                     "wait for upstream implementing RFC 5987")
    def test_russian_cp1251_user_agent(self):
        with self.app.test_client() as c:
            headers = [('User-Agent', u'ЯЙЮя'.encode('cp1251'))]
            response = c.get('/', headers=headers)
            self.assertEqual(response.data.decode('utf-8'), u'Welcome!')

    def test_make_secure_token_default_key(self):
        with self.app.test_request_context():
            self.assertEqual(make_secure_token('foo'),
                             '0f05743a2b617b2625362ab667c0dbdf4c9ec13a')

    def test_user_context_processor(self):
        self.assertEqual(_user_context_processor(), {'current_user': None})


class TestLoginUrlGeneration(unittest.TestCase):
    def test_make_next_param(self):
        self.assertEqual('/profile',
                         make_next_param('/login', 'http://localhost/profile'))

        self.assertEqual('http://localhost/profile',
                         make_next_param('https://localhost/login',
                                         'http://localhost/profile'))

        self.assertEqual('http://localhost/profile',
                         make_next_param('http://accounts.localhost/login',
                                         'http://localhost/profile'))

    def test_login_url_generation(self):
        PROTECTED = 'http://localhost/protected'

        self.assertEqual('/login?n=%2Fprotected', login_url('/login',
                                                            PROTECTED, 'n'))

        self.assertEqual('/login?next=%2Fprotected', login_url('/login',
                                                               PROTECTED))

        expected = 'https://auth.localhost/login' + \
                   '?next=http%3A%2F%2Flocalhost%2Fprotected'
        self.assertEqual(expected,
                         login_url('https://auth.localhost/login', PROTECTED))

        self.assertEqual('/login?affil=cgnu&next=%2Fprotected',
                         login_url('/login?affil=cgnu', PROTECTED))

    def test_login_url_generation_with_view(self):
        app = Flask(__name__)
        login_manager = LoginManager()
        login_manager.init_app(app)

        @app.route('/login')
        def login():
            return ''

        with app.test_request_context():
            self.assertEqual('/login?next=%2Fprotected',
                             login_url('login', '/protected'))

    def test_login_url_no_next_url(self):
        self.assertEqual(login_url('/foo'), '/foo')


class CookieEncodingTestCase(unittest.TestCase):
    def test_cookie_encoding(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'deterministic'

        COOKIE = u'1|7d276051c1eec578ed86f6b8478f7f7d803a7970'

        with app.test_request_context():
            self.assertEqual(COOKIE, encode_cookie(u'1'))
            self.assertEqual(u'1', decode_cookie(COOKIE))
            self.assertIsNone(decode_cookie(u'Foo|BAD_BASH'))
            self.assertIsNone(decode_cookie(u'no bar'))


class ImplicitIdUser(UserMixin):
    def __init__(self, id):
        self.id = id


class ExplicitIdUser(UserMixin):
    def __init__(self, name):
        self.name = name


class UserMixinTestCase(unittest.TestCase):
    def test_default_values(self):
        user = ImplicitIdUser(1)
        self.assertTrue(user.is_active())
        self.assertTrue(user.is_authenticated())
        self.assertFalse(user.is_anonymous())

    def test_get_id_from_id_attribute(self):
        user = ImplicitIdUser(1)
        self.assertEqual(u'1', user.get_id())

    def test_get_id_not_implemented(self):
        user = ExplicitIdUser('Notch')
        self.assertRaises(NotImplementedError, lambda: user.get_id())

    def test_equality(self):
        first = ImplicitIdUser(1)
        same = ImplicitIdUser(1)
        different = ImplicitIdUser(2)

        # Explicitly test the equality operator
        self.assertTrue(first == same)
        self.assertFalse(first == different)
        self.assertFalse(first != same)
        self.assertTrue(first != different)

        self.assertFalse(first == u'1')
        self.assertTrue(first != u'1')


class AnonymousUserTestCase(unittest.TestCase):
    def test_values(self):
        user = AnonymousUserMixin()

        self.assertFalse(user.is_active())
        self.assertFalse(user.is_authenticated())
        self.assertTrue(user.is_anonymous())
        self.assertIsNone(user.get_id())
