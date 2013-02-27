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
from attest import Tests, raises, assert_hook
from contextlib import contextmanager
import json
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

login = Tests()

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

USER_TOKENS = dict((u.get_auth_token(), u) for u in USERS.itervalues())

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

@login.context
def app_context():
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

    with app.test_request_context():
        yield app


# internals

@login.test
def cookie_encoding(app):
    COOKIE = u"1|7d276051c1eec578ed86f6b8478f7f7d803a7970"
    assert encode_cookie(u"1") == COOKIE
    assert decode_cookie(COOKIE) == u"1"
    assert decode_cookie(u"Foo|BAD_HASH") is None
    assert decode_cookie(u"no bar") is None


@login.test
def next_reduction():
    assert (make_next_param("/login", "http://localhost/profile") ==
            "/profile")
    assert (make_next_param("https://localhost/login", "http://localhost/profile") ==
            "http://localhost/profile")
    assert (make_next_param("http://accounts.localhost/login",
                            "http://localhost/profile") ==
            "http://localhost/profile")


@login.test
def login_url_generation(app):
    PROTECTED = "http://localhost/protected"
    assert login_url("login", PROTECTED) == "/login?next=%2Fprotected"
    assert (login_url("https://auth.localhost/login", PROTECTED) ==
            "https://auth.localhost/login?next=http%3A%2F%2Flocalhost%2Fprotected")
    assert (login_url("/login?affil=cgnu", PROTECTED) ==
            "/login?affil=cgnu&next=%2Fprotected")


@login.test
def create_identifier_json_serializeable(app):
    assert isinstance(json.dumps(_create_identifier()), basestring)


# login manager

@login.test
def lm_creation_and_setup(app):
    lm = LoginManager()
    lm.setup_app(app)
    assert app.login_manager is lm
    assert lm._load_user in app.before_request_funcs[None]
    assert lm._update_remember_cookie in app.after_request_funcs[None]


# unauthorization

@login.test
def unauthorized_401(app):
    lm = LoginManager()
    lm.setup_app(app)
    with raises(Unauthorized):
        with assert_fired(user_unauthorized):
            res = lm.unauthorized()


@login.test
def unauthorized_redirect(app):
    lm = LoginManager()
    lm.login_view = "login"
    lm.setup_app(app)
    res = lm.unauthorized()
    assert res.headers["Location"] == "/login?next=%2F"
    assert LOGIN_MESSAGE in get_flashed_messages()


@login.test
def login_message(app):
    lm = LoginManager()
    lm.login_view = "login"
    lm.login_message = u"Log in or the owl will eat you."
    lm.setup_app(app)
    lm.unauthorized()
    assert u"Log in or the owl will eat you." in get_flashed_messages()


@login.test
def unauthorized_callback(app):
    lm = LoginManager()
    lm.login_view = "login"
    @lm.unauthorized_handler
    def unauth():
        return "UNAUTHORIZED!"
    lm.setup_app(app)
    assert lm.unauthorized() == "UNAUTHORIZED!"
    assert len(get_flashed_messages()) == 0


# logging in and out

@login.test
def logging_in(app):
    lm = LoginManager()
    lm.login_view = "login"
    lm.user_loader(get_user)
    lm.setup_app(app)
    app.preprocess_request()
    assert not current_user.is_authenticated()
    assert current_user.is_anonymous()
    with assert_fired(user_logged_in):
        login_user(notch)
    assert current_user.name == u"Notch"
    assert session["user_id"] == u"1"


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


@login.test
def interactive(app):
    setup_interactive(app)
    # login workflow
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 1})
        print rv.data
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        rv = c.get("/protected")
        assert rv.data == u"Welcome, Notch"
        with assert_fired(user_logged_out):
            rv = c.get("/logout")
            assert rv.data == u"Logged out"
            assert "user_id" not in session


@login.test
def inactive_interactive(app):
    setup_interactive(app)
    # login workflow
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 3})
        assert rv.data == u"Go away, creeper"
        assert "user_id" not in session
        rv = c.get("/protected")
        assert rv.data == u"UNAUTHORIZED!"
        rv = c.get("/login", query_string={"id": 3, "force": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"3"
        assert session["_fresh"] is True
        rv = c.get("/protected")
        assert rv.data == u"Welcome, Creeper"
        rv = c.get("/logout")
        assert rv.data == u"Logged out"
        assert "user_id" not in session


@login.test
def remember_interactive(app):
    setup_interactive(app)
    with app.test_client() as c:
        COOKIE = u"1|7d276051c1eec578ed86f6b8478f7f7d803a7970"
        rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        cookies = get_cookies(rv)
        assert "remember_token" in cookies
        assert cookies["remember_token"] == COOKIE
        # testing remembrance
        c.cookie_jar.clear_session_cookies()
        rv = c.get("/protected")
        assert session["user_id"] == u"1"
        assert session["_fresh"] is False
        # testing reauthentication
        with assert_fired(user_login_confirmed):
            rv = c.get("/reauth")
        assert session["_fresh"] is True


@login.test
def loaded_from_cookie_signal(app):
    setup_interactive(app)
    with app.test_client() as c:
        c.get("/login", query_string={"id": 1, "remember": "yes"})
        c.cookie_jar.clear_session_cookies()
        with assert_fired(user_loaded_from_cookie):
            c.get("/protected")


@login.test
def change_api_key(app):
    setup_interactive(app)
    with app.test_client() as c:
        c.get("/login", query_string={"id": 1, "remember": "yes"})
        c.cookie_jar.clear_session_cookies()
        app.config["SECRET_KEY"] = "dffdf"
        with assert_fired(user_loaded_from_cookie):
            c.get("/protected")


@login.test
def static_interactive(app):
    setup_interactive(app)
    with app.test_client() as c:
        rv = c.get("/static/style.css")
        assert rv.data == 'static content'
        assert current_user.is_anonymous()


@login.test
def auth_token_interactive(app):
    setup_interactive(app)
    app.login_manager.token_loader(get_user_by_token)
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        cookies = get_cookies(rv)
        print cookies
        assert "remember_token" in cookies
        assert cookies["remember_token"] == notch.get_auth_token()
        # testing remembrance
        c.cookie_jar.clear_session_cookies()
        rv = c.get("/protected")
        assert session["user_id"] == u"1"
        assert session["_fresh"] is False


@login.test
def chinese_user_agent(app):
    setup_interactive(app)
    with app.test_client() as c:
        rv = c.get("/", headers=[("User-Agent", u"中文")])
        assert rv.data == u"The index"


@login.test
def russian_cp1251_user_agent(app):
    setup_interactive(app)
    with app.test_client() as c:
        rv = c.get("/", headers=[("User-Agent", u'ЯЙЮя'.encode('cp1251'))])
        assert rv.data == u"The index"

# session protection

@login.test
def basic_session_protection(app):
    setup_interactive(app)
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        with assert_fired(session_protected):
            rv = c.get("/protected", headers=[("User-Agent", "not the same")])
        assert rv.data == u"Welcome, Notch"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is False
        with assert_fired(user_login_confirmed):
            rv = c.get("/reauth", headers=[("User-Agent", "updated agent")])
        assert session["_fresh"] is True
        rv = c.get("/sensitive-action", headers=[("User-Agent", "updated agent")])
        assert rv.data == u"Be careful, Notch"


@login.test
def strong_session_protection(app):
    setup_interactive(app)
    app.login_manager.session_protection = "strong"
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 1, "remember": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        with assert_fired(session_protected):
            rv = c.get("/protected", headers=[("User-Agent", "not the same")])
        assert rv.data == u"UNAUTHORIZED!"
        assert "user_id" not in session


@login.test
def permanent_strong_session_protection(app):
    setup_interactive(app)
    app.login_manager.session_protection = "strong"
    with app.test_client() as c:
        rv = c.get("/login", query_string={"id": 1, "remember": "yes",
                                           "permanent": "yes"})
        assert rv.data == u"Logged in"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is True
        with assert_fired(session_protected):
            rv = c.get("/protected", headers=[("User-Agent", "not the same")])
        assert rv.data == u"Welcome, Notch"
        assert session["user_id"] == u"1"
        assert session["_fresh"] is False


# user objects

@login.test
def user_mixin():
    class MyUser(UserMixin):
        def __init__(self, id):
            self.id = id

    user = MyUser(1)
    assert user.is_authenticated()
    assert user.is_active()
    assert not user.is_anonymous()
    assert user.get_id() == u"1"

@login.test
def user_equality():
    class MyUser(UserMixin):
        def __init__(self, id):
            self.id = id

    idOneA = MyUser(1)
    idOneB = MyUser(1)
    idTwo = MyUser(2)

    assert idOneA == idOneA
    assert idOneA == idOneB
    assert idOneA != idTwo

@login.test
def anonymous_user():
    anon = AnonymousUser()
    assert not anon.is_authenticated()
    assert not anon.is_active()
    assert anon.is_anonymous()
    assert anon.get_id() is None


if __name__ == '__main__':
    login.main()
