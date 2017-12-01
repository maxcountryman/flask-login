# -*- coding: utf-8 -*-
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import base64
import collections
from datetime import timedelta, datetime
from contextlib import contextmanager
from mock import ANY
from semantic_version import Version


from werkzeug import __version__ as werkzeug_version
from flask import (
    Flask,
    Blueprint,
    Response,
    session,
    get_flashed_messages,
)
from flask.views import MethodView

from flask_login import (LoginManager, UserMixin, AnonymousUserMixin,
                         current_user, login_user, logout_user, user_logged_in,
                         user_logged_out, user_loaded_from_cookie,
                         user_login_confirmed, user_loaded_from_header,
                         user_loaded_from_request, user_unauthorized,
                         user_needs_refresh, make_next_param, login_url,
                         login_fresh, login_required, session_protected,
                         fresh_login_required, confirm_login, encode_cookie,
                         decode_cookie, set_login_view, user_accessed)
from flask_login.__about__ import (__title__, __description__, __url__,
                                   __version_info__, __version__, __author__,
                                   __author_email__, __maintainer__,
                                   __license__, __copyright__)
from flask_login.utils import _secret_key, _user_context_processor


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
                    'Got ({0}) expected ({1}, {2})'
                raise AssertionError(msg.format(self.heard[0], args, kwargs))

        def assert_heard_none(self, *args, **kwargs):
            ''' The signal fired no times '''
            if len(self.heard) >= 1:
                msg = '{0} signals were fired'.format(len(self.heard))
                raise AssertionError(msg)

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

    @property
    def is_active(self):
        return self.active


notch = User(u'Notch', 1)
steve = User(u'Steve', 2)
creeper = User(u'Creeper', 3, False)
germanjapanese = User(u'Müller', u'佐藤')  # Unicode user_id

USERS = {1: notch, 2: steve, 3: creeper, u'佐藤': germanjapanese}


class AboutTestCase(unittest.TestCase):
    """Make sure we can get version and other info."""

    def test_have_about_data(self):
        self.assertTrue(__title__ is not None)
        self.assertTrue(__description__ is not None)
        self.assertTrue(__url__ is not None)
        self.assertTrue(__version_info__ is not None)
        self.assertTrue(__version__ is not None)
        self.assertTrue(__author__ is not None)
        self.assertTrue(__author_email__ is not None)
        self.assertTrue(__maintainer__ is not None)
        self.assertTrue(__license__ is not None)
        self.assertTrue(__copyright__ is not None)


class StaticTestCase(unittest.TestCase):

    def test_static_loads_anonymous(self):
        app = Flask(__name__)
        app.static_url_path = '/static'
        app.secret_key = 'this is a temp key'
        lm = LoginManager()
        lm.init_app(app)

        with app.test_client() as c:
            c.get('/static/favicon.ico')
            self.assertTrue(current_user.is_anonymous)

    def test_static_loads_without_accessing_session(self):
        app = Flask(__name__)
        app.static_url_path = '/static'
        app.secret_key = 'this is a temp key'
        lm = LoginManager()
        lm.init_app(app)

        with app.test_client() as c:
            with listen_to(user_accessed) as listener:
                c.get('/static/favicon.ico')
                listener.assert_heard_none(app)


class InitializationTestCase(unittest.TestCase):
    ''' Tests the two initialization methods '''

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = '1234'

    def test_init_app(self):
        login_manager = LoginManager()
        login_manager.init_app(self.app, add_context_processor=True)

        self.assertIsInstance(login_manager, LoginManager)

    def test_class_init(self):
        login_manager = LoginManager(self.app, add_context_processor=True)

        self.assertIsInstance(login_manager, LoginManager)

    def test_login_disabled_is_set(self):
        login_manager = LoginManager(self.app, add_context_processor=True)
        self.assertFalse(login_manager._login_disabled)

    def test_no_user_loader_raises(self):
        login_manager = LoginManager(self.app, add_context_processor=True)
        with self.app.test_request_context():
            session['user_id'] = '2'
            with self.assertRaises(Exception) as cm:
                login_manager.reload_user()
            expected_exception_message = 'No user_loader has been installed'
            self.assertTrue(
                str(cm.exception).startswith(expected_exception_message))


class MethodViewLoginTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager._login_disabled = False

        class SecretEndpoint(MethodView):
            decorators = [
                login_required,
                fresh_login_required,
            ]

            def options(self):
                return u''

            def get(self):
                return u''

        self.app.add_url_rule('/secret',
                              view_func=SecretEndpoint.as_view('secret'))

    def test_options_call_exempt(self):
        with self.app.test_client() as c:
            result = c.open('/secret', method='OPTIONS')
            self.assertEqual(result.status_code, 200)


class LoginTestCase(unittest.TestCase):
    ''' Tests for results of the login_user function '''

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'deterministic'
        self.app.config['SESSION_PROTECTION'] = None
        self.remember_cookie_name = 'remember'
        self.app.config['REMEMBER_COOKIE_NAME'] = self.remember_cookie_name
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager._login_disabled = False

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
            if current_user.is_authenticated:
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

        @self.login_manager.header_loader
        def load_user_from_header(header_value):
            if header_value.startswith('Basic '):
                header_value = header_value.replace('Basic ', '', 1)
            try:
                user_id = base64.b64decode(header_value)
            except TypeError:
                pass
            return USERS.get(int(user_id))

        @self.login_manager.request_loader
        def load_user_from_request(request):
            user_id = request.args.get('user_id')
            try:
                user_id = int(float(user_id))
            except TypeError:
                pass
            return USERS.get(user_id)

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
            self.assertTrue(current_user.is_anonymous)

    def test_defaults_anonymous(self):
        with self.app.test_client() as c:
            result = c.get('/username')
            self.assertEqual(u'Anonymous', result.data.decode('utf-8'))

    def test_login_user(self):
        with self.app.test_request_context():
            result = login_user(notch)
            self.assertTrue(result)
            self.assertEqual(current_user.name, u'Notch')

    def test_login_user_not_fresh(self):
        with self.app.test_request_context():
            result = login_user(notch, fresh=False)
            self.assertTrue(result)
            self.assertEqual(current_user.name, u'Notch')
            self.assertIs(login_fresh(), False)

    def test_login_user_emits_signal(self):
        with self.app.test_request_context():
            with listen_to(user_logged_in) as listener:
                login_user(notch)
                listener.assert_heard_one(self.app, user=notch)

    def test_login_inactive_user(self):
        with self.app.test_request_context():
            result = login_user(creeper)
            self.assertTrue(current_user.is_anonymous)
            self.assertFalse(result)

    def test_login_inactive_user_forced(self):
        with self.app.test_request_context():
            login_user(creeper, force=True)
            self.assertEqual(current_user.name, u'Creeper')

    def test_login_user_with_header(self):
        user_id = 2
        user_name = USERS[user_id].name
        self.login_manager.request_callback = None
        with self.app.test_client() as c:
            basic_fmt = 'Basic {0}'
            decoded = bytes.decode(base64.b64encode(str.encode(str(user_id))))
            headers = [('Authorization', basic_fmt.format(decoded))]
            result = c.get('/username', headers=headers)
            self.assertEqual(user_name, result.data.decode('utf-8'))

    def test_login_invalid_user_with_header(self):
        user_id = 9000
        user_name = u'Anonymous'
        self.login_manager.request_callback = None
        with self.app.test_client() as c:
            basic_fmt = 'Basic {0}'
            decoded = bytes.decode(base64.b64encode(str.encode(str(user_id))))
            headers = [('Authorization', basic_fmt.format(decoded))]
            result = c.get('/username', headers=headers)
            self.assertEqual(user_name, result.data.decode('utf-8'))

    def test_login_user_with_request(self):
        user_id = 2
        user_name = USERS[user_id].name
        with self.app.test_client() as c:
            url = '/username?user_id={user_id}'.format(user_id=user_id)
            result = c.get(url)
            self.assertEqual(user_name, result.data.decode('utf-8'))

    def test_login_invalid_user_with_request(self):
        user_id = 9000
        user_name = u'Anonymous'
        with self.app.test_client() as c:
            url = '/username?user_id={user_id}'.format(user_id=user_id)
            result = c.get(url)
            self.assertEqual(user_name, result.data.decode('utf-8'))

    #
    # Logout
    #
    def test_logout_logs_out_current_user(self):
        with self.app.test_request_context():
            login_user(notch)
            logout_user()
            self.assertTrue(current_user.is_anonymous)

    def test_logout_emits_signal(self):
        with self.app.test_request_context():
            login_user(notch)
            with listen_to(user_logged_out) as listener:
                logout_user()
                listener.assert_heard_one(self.app, user=notch)

    def test_logout_without_current_user(self):
        with self.app.test_request_context():
            login_user(notch)
            del session['user_id']
            with listen_to(user_logged_out) as listener:
                logout_user()
                listener.assert_heard_one(self.app, user=ANY)

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

    def test_unauthorized_flash_message_localized(self):
        def _gettext(msg):
            if msg == u'Log in!':
                return u'Einloggen'

        self.login_manager.login_view = '/login'
        self.login_manager.localize_callback = _gettext
        self.login_manager.login_message = u'Log in!'

        expected_message = u'Einloggen'
        expected_category = self.login_manager.login_message_category = 'login'

        with self.app.test_client() as c:
            c.get('/secret')
            msgs = get_flashed_messages(category_filter=[expected_category])
            self.assertEqual([expected_message], msgs)
        self.login_manager.localize_callback = None

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

    def test_unauthorized_with_next_in_session(self):
        self.login_manager.login_view = 'login'
        self.app.config['USE_SESSION_FOR_NEXT'] = True

        @self.app.route('/login')
        def login():
            return session.pop('next', '')

        with self.app.test_client() as c:
            result = c.get('/secret')
            self.assertEqual(result.status_code, 302)
            self.assertEqual(result.location,
                             'http://localhost/login')
            self.assertEqual(c.get('/login').data.decode('utf-8'), '/secret')

    def test_unauthorized_uses_blueprint_login_view(self):
        with self.app.app_context():

            first = Blueprint('first', 'first')
            second = Blueprint('second', 'second')

            @self.app.route('/app_login')
            def app_login():
                return 'Login Form Goes Here!'

            @self.app.route('/first_login')
            def first_login():
                return 'Login Form Goes Here!'

            @self.app.route('/second_login')
            def second_login():
                return 'Login Form Goes Here!'

            @self.app.route('/protected')
            @login_required
            def protected():
                return u'Access Granted'

            @first.route('/protected')
            @login_required
            def first_protected():
                return u'Access Granted'

            @second.route('/protected')
            @login_required
            def second_protected():
                return u'Access Granted'

            self.app.register_blueprint(first, url_prefix='/first')
            self.app.register_blueprint(second, url_prefix='/second')

            set_login_view('app_login')
            set_login_view('first_login', blueprint=first)
            set_login_view('second_login', blueprint=second)

            with self.app.test_client() as c:

                result = c.get('/protected')
                self.assertEqual(result.status_code, 302)
                expected = ('http://localhost/'
                            'app_login?next=%2Fprotected')
                self.assertEqual(result.location, expected)

                result = c.get('/first/protected')
                self.assertEqual(result.status_code, 302)
                expected = ('http://localhost/'
                            'first_login?next=%2Ffirst%2Fprotected')
                self.assertEqual(result.location, expected)

                result = c.get('/second/protected')
                self.assertEqual(result.status_code, 302)
                expected = ('http://localhost/'
                            'second_login?next=%2Fsecond%2Fprotected')
                self.assertEqual(result.location, expected)

    def test_set_login_view_without_blueprints(self):
        with self.app.app_context():

            @self.app.route('/app_login')
            def app_login():
                return 'Login Form Goes Here!'

            @self.app.route('/protected')
            @login_required
            def protected():
                return u'Access Granted'

            set_login_view('app_login')

            with self.app.test_client() as c:

                result = c.get('/protected')
                self.assertEqual(result.status_code, 302)
                expected = 'http://localhost/app_login?next=%2Fprotected'
                self.assertEqual(result.location, expected)

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
        path = self.app.config['REMEMBER_COOKIE_PATH'] = '/mypath'
        domain = self.app.config['REMEMBER_COOKIE_DOMAIN'] = '.localhost.local'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')

            # TODO: Is there a better way to test this?
            self.assertIn(domain, c.cookie_jar._cookies,
                          'Custom domain not found as cookie domain')
            domain_cookie = c.cookie_jar._cookies[domain]
            self.assertIn(path, domain_cookie,
                          'Custom path not found as cookie path')
            path_cookie = domain_cookie[path]
            self.assertIn(name, path_cookie,
                          'Custom name not found as cookie name')
            cookie = path_cookie[name]

            expiration_date = datetime.utcfromtimestamp(cookie.expires)
            expected_date = datetime.utcnow() + duration
            difference = expected_date - expiration_date

            fail_msg = 'The expiration date {0} was far from the expected {1}'
            fail_msg = fail_msg.format(expiration_date, expected_date)
            self.assertLess(difference, timedelta(seconds=10), fail_msg)
            self.assertGreater(difference, timedelta(seconds=-10), fail_msg)

    def test_remember_me_with_duration_in_seconds_int(self):
        # e.g. 172800 is two days in seconds
        self.app.config['REMEMBER_COOKIE_DURATION'] = 172800

        with self.app.test_client() as c:
            result = c.get('/login-notch-remember')
            self.assertEqual(result.status_code, 200)

    def test_remember_me_with_duration_timedelta(self):
        from datetime import timedelta
        self.app.config['REMEMBER_COOKIE_DURATION'] = timedelta(seconds=172800)

        with self.app.test_client() as c:
            result = c.get('/login-notch-remember')
            self.assertEqual(result.status_code, 200)

    def test_remember_me_is_unfresh(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            self.assertEqual(u'False', c.get('/is-fresh').data.decode('utf-8'))

    def test_login_persists_with_signle_x_forwarded_for(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'
        with self.app.test_client() as c:
            c.get('/login-notch', headers=[('X-Forwarded-For', '10.1.1.1')])
            result = c.get('/username',
                           headers=[('X-Forwarded-For', '10.1.1.1')])
            self.assertEqual(u'Notch', result.data.decode('utf-8'))
            result = c.get('/username',
                           headers=[('X-Forwarded-For', '10.1.1.1')])
            self.assertEqual(u'Notch', result.data.decode('utf-8'))

    def test_login_persists_with_many_x_forwarded_for(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'
        with self.app.test_client() as c:
            c.get('/login-notch',
                  headers=[('X-Forwarded-For', '10.1.1.1')])
            result = c.get('/username',
                           headers=[('X-Forwarded-For', '10.1.1.1')])
            self.assertEqual(u'Notch', result.data.decode('utf-8'))
            result = c.get('/username',
                           headers=[('X-Forwarded-For', '10.1.1.1, 10.1.1.2')])
            self.assertEqual(u'Notch', result.data.decode('utf-8'))

    def test_user_loaded_from_cookie_fired(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            self._delete_session(c)
            with listen_to(user_loaded_from_cookie) as listener:
                c.get('/username')
                listener.assert_heard_one(self.app, user=notch)

    def test_user_loaded_from_header_fired(self):
        user_id = 1
        user_name = USERS[user_id].name
        self.login_manager.request_callback = None
        with self.app.test_client() as c:
            with listen_to(user_loaded_from_header) as listener:
                headers = [
                    (
                        'Authorization',
                        'Basic %s' % (
                            bytes.decode(
                                base64.b64encode(str.encode(str(user_id))))
                        ),
                    )
                ]
                result = c.get('/username', headers=headers)
                self.assertEqual(user_name, result.data.decode('utf-8'))
                listener.assert_heard_one(self.app, user=USERS[user_id])

    def test_user_loaded_from_request_fired(self):
        user_id = 1
        user_name = USERS[user_id].name
        with self.app.test_client() as c:
            with listen_to(user_loaded_from_request) as listener:
                url = '/username?user_id={user_id}'.format(user_id=user_id)
                result = c.get(url)
                self.assertEqual(user_name, result.data.decode('utf-8'))
                listener.assert_heard_one(self.app, user=USERS[user_id])

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

    def test_needs_refresh_flash_message_localized(self):
        def _gettext(msg):
            if msg == u'Refresh':
                return u'Aktualisieren'

        self.login_manager.refresh_view = '/refresh_view'
        self.login_manager.localize_callback = _gettext

        self.login_manager.needs_refresh_message = u'Refresh'
        self.login_manager.needs_refresh_message_category = 'refresh'
        category_filter = [self.login_manager.needs_refresh_message_category]

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            c.get('/needs-refresh')
            msgs = get_flashed_messages(category_filter=category_filter)
            self.assertIn(u'Aktualisieren', msgs)
        self.login_manager.localize_callback = None

    def test_needs_refresh_aborts_401(self):
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/needs-refresh')
            self.assertEqual(result.status_code, 401)

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

    def test_refresh_with_next_in_session(self):
        @self.app.route('/refresh-view')
        def refresh_view():
            return session.pop('next', '')

        self.login_manager.refresh_view = 'refresh_view'
        self.app.config['USE_SESSION_FOR_NEXT'] = True

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            result = c.get('/needs-refresh')
            self.assertEqual(result.status_code, 302)
            self.assertEqual(result.location, 'http://localhost/refresh-view')
            result = c.get('/refresh-view')
            self.assertEqual(result.data.decode('utf-8'), '/needs-refresh')

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
    def test_session_protection_basic_passes_successive_requests(self):
        self.app.config['SESSION_PROTECTION'] = 'basic'
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            username_result = c.get('/username')
            self.assertEqual(u'Notch', username_result.data.decode('utf-8'))
            fresh_result = c.get('/is-fresh')
            self.assertEqual(u'True', fresh_result.data.decode('utf-8'))

    def test_session_protection_strong_passes_successive_requests(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'
        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            username_result = c.get('/username')
            self.assertEqual(u'Notch', username_result.data.decode('utf-8'))
            fresh_result = c.get('/is-fresh')
            self.assertEqual(u'True', fresh_result.data.decode('utf-8'))

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

    def test_session_protection_basic_skips_when_remember_me(self):
        self.app.config['SESSION_PROTECTION'] = 'basic'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            # clear session to force remember me (and remove old session id)
            self._delete_session(c)
            # should not trigger protection because "sess" is empty
            with listen_to(session_protected) as listener:
                c.get('/username')
                listener.assert_heard_none(self.app)

    def test_session_protection_strong_skips_when_remember_me(self):
        self.app.config['SESSION_PROTECTION'] = 'strong'

        with self.app.test_client() as c:
            c.get('/login-notch-remember')
            # clear session to force remember me (and remove old session id)
            self._delete_session(c)
            # should not trigger protection because "sess" is empty
            with listen_to(session_protected) as listener:
                c.get('/username')
                listener.assert_heard_none(self.app)

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
            # write some unrelated data in the session, to ensure it does not
            # get destroyed
            with c.session_transaction() as sess:
                sess['foo'] = 'bar'
            c.get('/login-notch-remember')
            username_result = c.get('/username', headers=[('User-Agent',
                                                           'different')])
            self.assertEqual(u'Anonymous',
                             username_result.data.decode('utf-8'))
            with c.session_transaction() as sess:
                self.assertIn('foo', sess)
                self.assertEqual('bar', sess['foo'])

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

    def test_session_protection_skip_when_off_and_anonymous(self):
        with self.app.test_client() as c:
            # no user access
            with listen_to(user_accessed) as user_listener:
                results = c.get('/')
                user_listener.assert_heard_none(self.app)

            # access user with no session data
            with listen_to(session_protected) as session_listener:
                results = c.get('/username')
                self.assertEqual(results.data.decode('utf-8'), u'Anonymous')
                session_listener.assert_heard_none(self.app)

            # verify no session data has been set
            self.assertFalse(session)

    def test_session_protection_skip_when_basic_and_anonymous(self):
        self.app.config['SESSION_PROTECTION'] = 'basic'

        with self.app.test_client() as c:
            # no user access
            with listen_to(user_accessed) as user_listener:
                results = c.get('/')
                user_listener.assert_heard_none(self.app)

            # access user with no session data
            with listen_to(session_protected) as session_listener:
                results = c.get('/username')
                self.assertEqual(results.data.decode('utf-8'), u'Anonymous')
                session_listener.assert_heard_none(self.app)

            # verify no session data has been set
            self.assertFalse(session)

    #
    # Lazy Access User
    #
    def test_requests_without_accessing_session(self):
        with self.app.test_client() as c:
            c.get('/login-notch')

            # no session access
            with listen_to(user_accessed) as listener:
                c.get('/')
                listener.assert_heard_none(self.app)

            # should have a session access
            with listen_to(user_accessed) as listener:
                result = c.get('/username')
                listener.assert_heard_one(self.app)
                self.assertEqual(result.data.decode('utf-8'), u'Notch')

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

    def test_decorators_are_disabled(self):
        @self.app.route('/protected')
        @login_required
        @fresh_login_required
        def protected():
            return u'Access Granted'

        self.app.login_manager._login_disabled = True

        with self.app.test_client() as c:
            result = c.get('/protected')
            self.assertIn(u'Access Granted', result.data.decode('utf-8'))

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
            self.assertEqual(stale_result.status_code, 401)

            c.get('/confirm-login')
            refreshed_result = c.get('/very-protected')
            self.assertEqual(u'Access Granted',
                             refreshed_result.data.decode('utf-8'))

    #
    # Misc
    #
    @unittest.skipIf(Version(werkzeug_version) >= Version('0.9', partial=True),
                     "wait for upstream implementing RFC 5987")
    def test_chinese_user_agent(self):
        with self.app.test_client() as c:
            result = c.get('/', headers=[('User-Agent', u'中文')])
            self.assertEqual(u'Welcome!', result.data.decode('utf-8'))

    @unittest.skipIf(Version(werkzeug_version) >= Version('0.9', partial=True),
                     "wait for upstream implementing RFC 5987")
    def test_russian_cp1251_user_agent(self):
        with self.app.test_client() as c:
            headers = [('User-Agent', u'ЯЙЮя'.encode('cp1251'))]
            response = c.get('/', headers=headers)
            self.assertEqual(response.data.decode('utf-8'), u'Welcome!')

    def test_user_context_processor(self):
        with self.app.test_request_context():
            _ucp = self.app.context_processor(_user_context_processor)
            self.assertIsInstance(_ucp()['current_user'], AnonymousUserMixin)


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

        # COOKIE = u'1|7d276051c1eec578ed86f6b8478f7f7d803a7970'

        # Due to the restriction of 80 chars I have to break up the hash in two
        h1 = u'0e9e6e9855fbe6df7906ec4737578a1d491b38d3fd5246c1561016e189d6516'
        h2 = u'043286501ca43257c938e60aad77acec5ce916b94ca9d00c0bb6f9883ae4b82'
        h3 = u'ae'
        COOKIE = u'1|' + h1 + h2 + h3

        with app.test_request_context():
            self.assertEqual(COOKIE, encode_cookie(u'1'))
            self.assertEqual(u'1', decode_cookie(COOKIE))
            self.assertIsNone(decode_cookie(u'Foo|BAD_BASH'))
            self.assertIsNone(decode_cookie(u'no bar'))


class SecretKeyTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_bytes(self):
        self.app.config['SECRET_KEY'] = b'\x9e\x8f\x14'
        with self.app.test_request_context():
            self.assertEqual(_secret_key(), b'\x9e\x8f\x14')

    def test_native(self):
        self.app.config['SECRET_KEY'] = '\x9e\x8f\x14'
        with self.app.test_request_context():
            self.assertEqual(_secret_key(), b'\x9e\x8f\x14')

    def test_default(self):
        self.assertEqual(_secret_key('\x9e\x8f\x14'), b'\x9e\x8f\x14')


class ImplicitIdUser(UserMixin):
    def __init__(self, id):
        self.id = id


class ExplicitIdUser(UserMixin):
    def __init__(self, name):
        self.name = name


class UserMixinTestCase(unittest.TestCase):
    def test_default_values(self):
        user = ImplicitIdUser(1)
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_authenticated)
        self.assertFalse(user.is_anonymous)

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

    def test_hashable(self):
        self.assertTrue(isinstance(UserMixin(), collections.Hashable))


class AnonymousUserTestCase(unittest.TestCase):
    def test_values(self):
        user = AnonymousUserMixin()

        self.assertFalse(user.is_active)
        self.assertFalse(user.is_authenticated)
        self.assertTrue(user.is_anonymous)
        self.assertIsNone(user.get_id())


class UnicodeCookieUserIDTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'deterministic'
        self.app.config['SESSION_PROTECTION'] = None
        self.remember_cookie_name = 'remember'
        self.app.config['REMEMBER_COOKIE_NAME'] = self.remember_cookie_name
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager._login_disabled = False

        @self.app.route('/')
        def index():
            return u'Welcome!'

        @self.app.route('/login-germanjapanese-remember')
        def login_germanjapanese_remember():
            return unicode(login_user(germanjapanese, remember=True))

        @self.app.route('/username')
        def username():
            if current_user.is_authenticated:
                return current_user.name
            return u'Anonymous'

        @self.app.route('/userid')
        def user_id():
            if current_user.is_authenticated:
                return current_user.id
            return u'wrong_id'

        @self.login_manager.user_loader
        def load_user(user_id):
            return USERS[unicode(user_id)]

        # This will help us with the possibility of typoes in the tests. Now
        # we shouldn't have to check each response to help us set up state
        # (such as login pages) to make sure it worked: we will always
        # get an exception raised (rather than return a 404 response)
        @self.app.errorhandler(404)
        def handle_404(e):
            raise e

        unittest.TestCase.setUp(self)

    def _delete_session(self, c):
        # Helper method to cause the session to be deleted
        # as if the browser was closed. This will remove
        # the session regardless of the permament flag
        # on the session!
        with c.session_transaction() as sess:
            sess.clear()

    def test_remember_me_username(self):
        with self.app.test_client() as c:
            c.get('/login-germanjapanese-remember')
            self._delete_session(c)
            result = c.get('/username')
            self.assertEqual(u'Müller', result.data.decode('utf-8'))

    def test_remember_me_user_id(self):
        with self.app.test_client() as c:
            c.get('/login-germanjapanese-remember')
            self._delete_session(c)
            result = c.get('/userid')
            self.assertEqual(u'佐藤', result.data.decode('utf-8'))
