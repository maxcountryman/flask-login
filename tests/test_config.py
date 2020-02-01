import unittest

from flask import Flask, session

from flask_login import FlaskLoginClient, LoginManager, login_user, logout_user
from tests._models import USERS, notch


class DefaultConfigurationTestCase(unittest.TestCase):

    def _setup_flask(self):
        app = Flask(__name__)

        @app.route('/login')
        def login():
            login_user(notch)
            return u'User % logged in.'.format(notch.name)

        @app.route('/logout')
        def logout():
            logout_user()
            return u'User % logged out.'.format(notch.name)

        # This will help us with the possibility of typoes in the tests. Now
        # we shouldn't have to check each response to help us set up state
        # (such as login pages) to make sure it worked: we will always
        # get an exception raised (rather than return a 404 response)
        @app.errorhandler(404)
        def handle_404(e):
            raise e

        self.app = app

    def _setup_config(self):
        self.app.config.update({
            'SECRET_KEY': 'flask-secret',
            'REMEMBER_COOKIE_NAME': 'remember',
        })

    def _setup_login_manager(self):
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return USERS[int(user_id)]

        self.logging_manager = login_manager

    def _setup_test_client(self):
        self.app.test_client_class = FlaskLoginClient

    def setUp(self):
        self._setup_flask()
        self._setup_config()
        self._setup_login_manager()
        self._setup_test_client()

        unittest.TestCase.setUp(self)

    def test_user_id_key_in_config(self):
        with self.app.test_client() as c:
            c.get('/login')
            self.assertIn(self.logging_manager.user_id_key, session)
            c.get('/logout')


class CustomUserIDKeyConfigurationTestCase(unittest.TestCase):

    USER_ID_KEY = '_auth_user_id'

    def _setup_flask(self):
        app = Flask(__name__)

        @app.route('/login')
        def login():
            login_user(notch)
            return u'User % logged in.'.format(notch.name)

        @app.route('/logout')
        def logout():
            logout_user()
            return u'User % logged out.'.format(notch.name)

        # This will help us with the possibility of typoes in the tests. Now
        # we shouldn't have to check each response to help us set up state
        # (such as login pages) to make sure it worked: we will always
        # get an exception raised (rather than return a 404 response)
        @app.errorhandler(404)
        def handle_404(e):
            raise e

        self.app = app

    def _setup_config(self):
        self.app.config.update({
            'SECRET_KEY': 'flask-secret',
            'REMEMBER_COOKIE_NAME': 'remember',
            'USER_ID_KEY': self.USER_ID_KEY
        })

    def _setup_login_manager(self):
        login_manager = LoginManager()
        login_manager.init_app(self.app)

        @login_manager.user_loader
        def load_user(user_id):
            return USERS[int(user_id)]

        self.logging_manager = login_manager

    def _setup_test_client(self):
        self.app.test_client_class = FlaskLoginClient

    def setUp(self):
        self._setup_flask()
        self._setup_config()
        self._setup_login_manager()
        self._setup_test_client()

        unittest.TestCase.setUp(self)

    def test_user_id_key_in_config(self):
        with self.app.test_client() as c:
            c.get('/login')
            self.assertIn(self.logging_manager.user_id_key, session)
            c.get('/logout')
