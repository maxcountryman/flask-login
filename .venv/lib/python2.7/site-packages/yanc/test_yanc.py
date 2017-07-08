# Copyright 2011-2014 Arthur Noel
#
# This file is part of Yanc.
#
# Yanc is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# Yanc is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Yanc. If not, see <http://www.gnu.org/licenses/>.

import difflib

import re
import unittest

from nose.plugins import PluginTester

try:
    import unittest2
except ImportError:
    pass
else:  # pragma: no cover - unittest shim for those that don't have it
    import sys
    sys.modules["unittest"] = unittest2

from yanc.yancplugin import YancPlugin


EXCEPTION_PLAIN = """EF
======================================================================
ERROR: runTest (yanc.test_yanc.TC1)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "test_yanc.py", line 1, in runTest
    raise ValueError("xxx")
ValueError: xxx

======================================================================
FAIL: runTest (yanc.test_yanc.TC2)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "test_yanc.py", line 1, in runTest
    self.assertTrue(False)
AssertionError

----------------------------------------------------------------------
Ran 2 tests in 0.001s

FAILED (errors=1, failures=1)
"""

EXCEPTION_COLOR = """\x1b[31mE\x1b[0m\x1b[33mF\x1b[0m
\x1b[34m======================================================================\x1b[0m
\x1b[31mERROR:\x1b[0m runTest (yanc.test_yanc.TC1)
\x1b[34m----------------------------------------------------------------------\x1b[0m
Traceback (most recent call last):
  File "test_yanc.py", line 1, in runTest
    raise ValueError("xxx")
ValueError: xxx

\x1b[34m======================================================================\x1b[0m
\x1b[33mFAIL:\x1b[0m runTest (yanc.test_yanc.TC2)
\x1b[34m----------------------------------------------------------------------\x1b[0m
Traceback (most recent call last):
  File "test_yanc.py", line 1, in runTest
    self.assertTrue(False)
AssertionError

\x1b[34m----------------------------------------------------------------------\x1b[0m
Ran 2 tests in 0.001s

\x1b[31mFAILED\x1b[0m (\x1b[31merrors=1\x1b[0m, \x1b[33mfailures=1\x1b[0m)
"""

FILE_PATTERN = re.compile('File "[^"]+", line \d+')
TIME_PATTEN = re.compile("\d+\.\d+s")
ASSERTIONERROR_PATTERN = re.compile("AssertionError.*")


class _TestYanc(PluginTester, unittest.TestCase):

    activate = '--with-yanc'

    plugins = [YancPlugin()]

    exc_str = EXCEPTION_COLOR

    def makeSuite(self):

        class TC1(unittest.TestCase):
            def runTest(self):
                raise ValueError("xxx")

        class TC2(unittest.TestCase):
            def runTest(self):
                self.assertTrue(False)

        return unittest.TestSuite([TC1(), TC2()])

    def test_yanc(self):
        exc_str = FILE_PATTERN.sub('File "test_yanc.py", line 1',
                                   str(self.output))
        exc_str = TIME_PATTEN.sub("0.001s", exc_str)
        exc_str = ASSERTIONERROR_PATTERN.sub("AssertionError", exc_str)
        if self.exc_str != exc_str:  # pragma: no cover - only hit on fail
            diff = difflib.unified_diff(self.exc_str.splitlines(True),
                                        exc_str.splitlines(True),
                                        "expected", "actual")
            self.fail("".join(diff))


class TestYancColorAuto(_TestYanc):
    args = ()


class TestYancColorOn(_TestYanc):
    args = ('--yanc-color=on',)


class TestYancColorOff(_TestYanc):
    args = ('--yanc-color=off',)
    exc_str = EXCEPTION_PLAIN
