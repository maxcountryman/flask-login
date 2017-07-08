# -*- coding: utf-8 -*-
# Copyright (c) The python-semanticversion project
# This code is distributed under the two-clause BSD License.


def base_cmp(x, y):
    if x == y:
        return 0
    elif x > y:
        return 1
    elif x < y:
        return -1
    else:
        # Fix Py2's behavior: cmp(x, y) returns -1 for unorderable types
        return NotImplemented
