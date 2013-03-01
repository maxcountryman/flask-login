from flask import Flask
from flask.ext.login import LoginManager

import unittest


class LoginTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        unittest.TestCase.setUp(self)

    def test_user_loader(self):
        pass

    def test_token_loader(self):
        pass

    def test_setup_app(self):
        pass

    def test_init_app(self):
        pass

    def test_unauthorized_handler(self):
        pass

    def test_unauthorized(self):
        pass

    def test_needs_refresh_handler(self):
        pass

    def test_needs_refresh(self):
        pass

    def test_reload_user(self):
        pass

    def test_load_user(self):
        pass

    def test_session_protection(self):
        pass

    def test_load_from_cookie(self):
        pass

    def test_update_remember_cookie(self):
        pass

    def test_set_cookie(self):
        pass

    def test_user_cookie(self):
        pass


class UserTestCase(unittest.TestCase):
    pass


class AnonymousUserTestCase(unittest.TestCase):
    pass
