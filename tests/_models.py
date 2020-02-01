#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask_login import UserMixin


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


class ImplicitIdUser(UserMixin):
    def __init__(self, id):
        self.id = id


class ExplicitIdUser(UserMixin):
    def __init__(self, name):
        self.name = name


notch = User(u'Notch', 1)
steve = User(u'Steve', 2)
creeper = User(u'Creeper', 3, False)
germanjapanese = User(u'Müller', u'佐藤')

USERS = {1: notch, 2: steve, 3: creeper, u'佐藤': germanjapanese}
