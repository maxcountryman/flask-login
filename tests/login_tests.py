# -*- coding: utf-8 -*-
"""
Flask-Login Tests
=================
These tests use Attest, because it's approximately twenty times cooler than
anything related to unittest.

:copyright: (C) 2011 by Matthew Frazier.
:license:   MIT/X11, see LICENSE for more details.
"""
from __future__ import with_statement

import json

from contextlib import contextmanager
from unittest import TestCase

from flask import (Flask, session, get_flashed_messages, url_for, request,
                   signals_available)
from flask.views import MethodView
from flask.ext.login import (
    encode_cookie, decode_cookie, make_next_param, login_url, LoginManager,
    login_user, logout_user, current_user, login_required, LoginRequiredMixin,
    LOGIN_MESSAGE, confirm_login, UserMixin, AnonymousUser, make_secure_token,
    user_logged_in, user_logged_out, user_loaded_from_cookie,
    user_login_confirmed,  user_unauthorized, user_needs_refresh,
    session_protected, fresh_login_required, _create_identifier
)
from werkzeug.exceptions import Unauthorized
from werkzeug.utils import parse_cookie

# login = Tests()

# utilities

class User(UserMixin):
    def __init__(self, name, id, active=True):
        self.id = id
        self.name = name
        self.active = active

    def is_active(self):
        return self.active

    def get_auth_token(self):
        return make_secure_token(self.name, key="deterministic")

notch = User(u"Notch", 1)
steve = User(u"Steve", 2)
creeper = User(u"Creeper", 3, False)

USERS = {1: notch, 2: steve, 3: creeper}

USER_TOKENS = dict((u.get_auth_token(), u) for u in USERS.values())

def get_user(id):
    return USERS.get(int(id))

def get_user_by_token(token):
    return USER_TOKENS.get(token)


@contextmanager
def assert_fired(signal, l=None):
    if signals_available:
        if l is None:
            l = []
        def _handler(sender, **kwargs):
            l.append(kwargs)
        with signal.connected_to(_handler):
            yield
        assert len(l) > 0
    else:
        yield


# contexts

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "deterministic"
    app.config["TESTING"] = True
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["DEBUG"] = True

    @app.route("/")
    def index():
        return u"The index"

    @app.route("/login")
    def login():
        id = int(request.args["id"])
        force = "force" in request.args
        remember = "remember" in request.args
        if login_user(USERS[id], force=force, remember=remember):
            if "permanent" in request.args:
                session.permanent = True
            return u"Logged in"
        else:
            return u"Go away, creeper"

    class Protected(LoginRequiredMixin, MethodView):
        def get(self):
            return u"Welcome, %s" % current_user.name
    app.add_url_rule('/protected', view_func=Protected.as_view('protected'))

    @app.route("/sensitive-action")
    @fresh_login_required
    def sensitive_action():
        return u"Be careful, %s" % current_user.name

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return u"Logged out"

    @app.route("/reauth")
    @login_required
    def reauth():
        confirm_login()
        return u"Login confirmed"

    return app


class FlaskLoginTestCase(TestCase):
    def setUp(self):
        self.app = create_app()
        self.context = self.app.test_request_context()
        self.context.push()

    def tearDown(self):
        self.context.pop()


# internals
class InternalsTestCase(FlaskLoginTestCase):

    def test_cookie_encoding(self):
        COOKIE = u"1|7d276051c1eec578ed86f6b8478f7f7d803a7970"
        self.assertEquals(encode_cookie(u"1"), COOKIE)
        self.assertEquals(decode_cookie(COOKIE), u"1")
        self.assertIsNone(decode_cookie(u"Foo|BAD_HASH"))
        self.assertIsNone(decode_cookie(u"no bar"))

    def test_next_reduction(self):
        self.assertEquals(make_next_param("/login", "http://localhost/profile"), "/profile")
        self.assertEquals(make_next_param("https://localhost/login", "http://localhost/profile"), "http://localhost/profile")
        self.assertEquals(make_next_param("http://accounts.localhost/login", "http://localhost/profile"), "http://localhost/profile")

    def test_login_url_generation(self):
        PROTECTED = "http://localhost/protected"
        self.assertEquals(login_url("login", PROTECTED), "/login?next=%2Fprotected")
        self.assertEquals(login_url("https://auth.localhost/login", PROTECTED), "https://auth.localhost/login?next=http%3A%2F%2Flocalhost%2Fprotected")
        self.assertEquals(login_url("/login?affil=cgnu", PROTECTED), "/login?affil=cgnu&next=%2Fprotected")

    def test_create_identifier_json_serializeable(self):
        self.assertTrue(isinstance(json.dumps(_create_identifier()), str))

    def test_lm_creation_and_setup(self):
        lm = LoginManager()
        lm.setup_app(self.app)
        self.assertEquals(self.app.login_manager, lm)
        self.assertIn(lm._load_user, self.app.before_request_funcs[None])
        self.assertIn(lm._update_remember_cookie, self.app.after_request_funcs[None])

    def test_unauthorized_401(self):
        lm = LoginManager()
        lm.setup_app(self.app)
        with assert_fired(user_unauthorized):
            self.assertRaises(Unauthorized, lm.unauthorized)

    def test_unauthorized_redirect(self):
        lm = LoginManager()
        lm.login_view = "login"
        lm.setup_app(self.app)
        res = lm.unauthorized()
        self.assertEquals(res.headers["Location"], "/login?next=%2F")
        self.assertIn(LOGIN_MESSAGE, get_flashed_messages())

    def test_login_message(self):
        lm = LoginManager()
        lm.login_view = "login"
        lm.login_message = u"Log in or the owl will eat you."
        lm.setup_app(self.app)
        lm.unauthorized()
        self.assertIn(u"Log in or the owl will eat you.", get_flashed_messages())

    def unauthorized_callback(self):
        lm = LoginManager()
        lm.login_view = "login"
        @lm.unauthorized_handler
        def unauth():
            return "UNAUTHORIZED!"
        lm.setup_app(self.app)
        self.assertEquals(lm.unauthorized(), "UNAUTHORIZED!")
        self.assertEquals(len(get_flashed_messages()), 0)

    def test_logging_in(self):
        lm = LoginManager()
        lm.login_view = "login"
        lm.user_loader(get_user)
        lm.setup_app(self.app)
        self.app.preprocess_request()
        self.assertFalse(current_user.is_authenticated())
        self.assertTrue(current_user.is_anonymous())
        with assert_fired(user_logged_in):
            login_user(notch)
        self.assertEquals(current_user.name, u"Notch")
        self.assertEquals(session["user_id"], u"1")


# interactive testing

def setup_interactive(app):
    lm = LoginManager()
    lm.login_view = "login"
    lm.user_loader(get_user)
    @lm.unauthorized_handler
    def unauth():
        return "UNAUTHORIZED!"
    lm.setup_app(app)


def get_cookies(rv):
    cookies = {}
    for value in rv.headers.get_all("Set-Cookie"):
        cookies.update(parse_cookie(value))
    return cookies


class InteractiveTestCase(FlaskLoginTestCase):

    def test_interactive(self):
        setup_interactive(self.app)
        # login workflow
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 1})
            # print rv.data
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            rv = c.get("/protected")
            self.assertEquals(rv.data, b"Welcome, Notch")
            with assert_fired(user_logged_out):
                rv = c.get("/logout")
                self.assertEquals(rv.data, b"Logged out")
                self.assertNotIn("user_id", session)

    def test_inactive_interactive(self):
        setup_interactive(self.app)
        # login workflow
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 3})
            self.assertEquals(rv.data, b"Go away, creeper")
            self.assertNotIn("user_id", session)
            rv = c.get("/protected")
            self.assertEquals(rv.data, b"UNAUTHORIZED!")
            rv = c.get("/login", query_string={"id": 3, "force": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"3")
            self.assertTrue(session["_fresh"])
            rv = c.get("/protected")
            self.assertEquals(rv.data, b"Welcome, Creeper")
            rv = c.get("/logout")
            self.assertEquals(rv.data, b"Logged out")
            self.assertNotIn("user_id", session)

    def test_remember_interactive(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            COOKIE = u"1|7d276051c1eec578ed86f6b8478f7f7d803a7970"
            rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            cookies = get_cookies(rv)
            self.assertIn("remember_token", cookies)
            self.assertEquals(cookies["remember_token"], COOKIE)
            # testing remembrance
            c.cookie_jar.clear_session_cookies()
            rv = c.get("/protected")
            self.assertEquals(session["user_id"], u"1")
            self.assertFalse(session["_fresh"])
            # testing reauthentication
            with assert_fired(user_login_confirmed):
                rv = c.get("/reauth")
            self.assertTrue(session["_fresh"])

    def test_loaded_from_cookie_signal(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            c.get("/login", query_string={"id": 1, "remember": "yes"})
            c.cookie_jar.clear_session_cookies()
            with assert_fired(user_loaded_from_cookie):
                c.get("/protected")

    def test_change_api_key(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            c.get("/login", query_string={"id": 1, "remember": "yes"})
            c.cookie_jar.clear_session_cookies()
            self.app.config["SECRET_KEY"] = "dffdf"
            rv = c.get("/protected")
            self.assertEquals(rv.data, b'UNAUTHORIZED!')

    def test_static_interactive(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            rv = c.get("/static/style.css")
            self.assertEquals(rv.data, b'static content')
            self.assertTrue(current_user.is_anonymous())

    def test_auth_token_interactive(self):
        setup_interactive(self.app)
        self.app.login_manager.token_loader(get_user_by_token)
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            cookies = get_cookies(rv)
            self.assertIn("remember_token", cookies)
            self.assertEquals(cookies["remember_token"], notch.get_auth_token())
            # testing remembrance
            c.cookie_jar.clear_session_cookies()
            rv = c.get("/protected")
            self.assertEquals(session["user_id"], u"1")
            self.assertFalse(session["_fresh"])

    def test_chinese_user_agent(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            rv = c.get("/", headers=[("User-Agent", u"中文")])
            self.assertEquals(rv.data, b"The index")

    def test_russian_cp1251_user_agent(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            rv = c.get("/", headers=[("User-Agent", u'ЯЙЮя'.encode('cp1251'))])
            self.assertEquals(rv.data, b"The index")

    def test_basic_session_protection(self):
        setup_interactive(self.app)
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            with assert_fired(session_protected):
                rv = c.get("/protected", headers=[("User-Agent", "not the same")])
            self.assertEquals(rv.data, b"Welcome, Notch")
            self.assertEquals(session["user_id"], u"1")
            self.assertFalse(session["_fresh"])
            with assert_fired(user_login_confirmed):
                rv = c.get("/reauth", headers=[("User-Agent", "updated agent")])
            self.assertTrue(session["_fresh"])
            rv = c.get("/sensitive-action", headers=[("User-Agent", "updated agent")])
            self.assertEquals(rv.data, b"Be careful, Notch")

    def test_strong_session_protection(self):
        setup_interactive(self.app)
        self.app.login_manager.session_protection = "strong"
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            with assert_fired(session_protected):
                rv = c.get("/protected", headers=[("User-Agent", "not the same")])
            self.assertEquals(rv.data, b"UNAUTHORIZED!")
            self.assertNotIn("user_id", session)

    def test_permanent_strong_session_protection(self):
        setup_interactive(self.app)
        self.app.login_manager.session_protection = "strong"
        with self.app.test_client() as c:
            rv = c.get("/login", query_string={"id": 1, "remember": "yes",
                                               "permanent": "yes"})
            self.assertEquals(rv.data, b"Logged in")
            self.assertEquals(session["user_id"], u"1")
            self.assertTrue(session["_fresh"])
            with assert_fired(session_protected):
                rv = c.get("/protected", headers=[("User-Agent", "not the same")])
            self.assertEquals(rv.data, b"Welcome, Notch")
            self.assertEquals(session["user_id"], u"1")
            self.assertFalse(session["_fresh"], False)

    def test_user_mixin(self):
        class MyUser(UserMixin):
            def __init__(self, id):
                self.id = id

        user = MyUser(1)
        self.assertTrue(user.is_authenticated())
        self.assertTrue(user.is_active())
        self.assertFalse(user.is_anonymous())
        self.assertEquals(user.get_id(), u"1")

    def test_user_equality(self):
        class MyUser(UserMixin):
            def __init__(self, id):
                self.id = id

        idOneA = MyUser(1)
        idOneB = MyUser(1)
        idTwo = MyUser(2)

        self.assertEquals(idOneA, idOneA)
        self.assertEquals(idOneA, idOneB)
        self.assertNotEqual(idOneA, idTwo)

    def anonymous_user():
        anon = AnonymousUser()
        self.assertFalse(anon.is_authenticated())
        self.assertFalse(anon.is_active())
        self.assertTrue(anon.is_anonymous())
        self.assertIsNone(anon.get_id())
