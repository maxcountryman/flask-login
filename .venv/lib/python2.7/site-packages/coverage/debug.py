# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://bitbucket.org/ned/coveragepy/src/default/NOTICE.txt

"""Control of and utilities for debugging."""

import contextlib
import inspect
import os
import re
import sys

from coverage.misc import isolate_module

os = isolate_module(os)


# When debugging, it can be helpful to force some options, especially when
# debugging the configuration mechanisms you usually use to control debugging!
# This is a list of forced debugging options.
FORCED_DEBUG = []

# A hack for debugging testing in sub-processes.
_TEST_NAME_FILE = ""    # "/tmp/covtest.txt"


class DebugControl(object):
    """Control and output for debugging."""

    def __init__(self, options, output):
        """Configure the options and output file for debugging."""
        self.options = options
        self.output = output
        self.suppress_callers = False

    def __repr__(self):
        return "<DebugControl options=%r output=%r>" % (self.options, self.output)

    def should(self, option):
        """Decide whether to output debug information in category `option`."""
        if option == "callers" and self.suppress_callers:
            return False
        return (option in self.options or option in FORCED_DEBUG)

    @contextlib.contextmanager
    def without_callers(self):
        """A context manager to prevent call stacks from being logged."""
        old = self.suppress_callers
        self.suppress_callers = True
        try:
            yield
        finally:
            self.suppress_callers = old

    def write(self, msg):
        """Write a line of debug output.

        `msg` is the line to write. A newline will be appended.

        """
        if self.should('pid'):
            msg = "pid %5d: %s" % (os.getpid(), msg)
        self.output.write(msg+"\n")
        if self.should('callers'):
            dump_stack_frames(out=self.output, skip=1)
        self.output.flush()

    def write_formatted_info(self, header, info):
        """Write a sequence of (label,data) pairs nicely."""
        self.write(info_header(header))
        for line in info_formatter(info):
            self.write(" %s" % line)


def info_header(label):
    """Make a nice header string."""
    return "--{0:-<60s}".format(" "+label+" ")


def info_formatter(info):
    """Produce a sequence of formatted lines from info.

    `info` is a sequence of pairs (label, data).  The produced lines are
    nicely formatted, ready to print.

    """
    info = list(info)
    if not info:
        return
    label_len = max(len(l) for l, _d in info)
    for label, data in info:
        if data == []:
            data = "-none-"
        if isinstance(data, (list, set, tuple)):
            prefix = "%*s:" % (label_len, label)
            for e in data:
                yield "%*s %s" % (label_len+1, prefix, e)
                prefix = ""
        else:
            yield "%*s: %s" % (label_len, label, data)


def short_stack(limit=None, skip=0):
    """Return a string summarizing the call stack.

    The string is multi-line, with one line per stack frame. Each line shows
    the function name, the file name, and the line number:

        ...
        start_import_stop : /Users/ned/coverage/trunk/tests/coveragetest.py @95
        import_local_file : /Users/ned/coverage/trunk/tests/coveragetest.py @81
        import_local_file : /Users/ned/coverage/trunk/coverage/backward.py @159
        ...

    `limit` is the number of frames to include, defaulting to all of them.

    `skip` is the number of frames to skip, so that debugging functions can
    call this and not be included in the result.

    """
    stack = inspect.stack()[limit:skip:-1]
    return "\n".join("%30s : %s @%d" % (t[3], t[1], t[2]) for t in stack)


def dump_stack_frames(limit=None, out=None, skip=0):
    """Print a summary of the stack to stdout, or some place else."""
    out = out or sys.stdout
    out.write(short_stack(limit=limit, skip=skip+1))
    out.write("\n")


def log(msg, stack=False):                                  # pragma: debugging
    """Write a log message as forcefully as possible."""
    with open("/tmp/covlog.txt", "a") as f:
        f.write("{pid}: {msg}\n".format(pid=os.getpid(), msg=msg))
        if stack:
            dump_stack_frames(out=f, skip=1)


def enable_aspectlib_maybe():                               # pragma: debugging
    """For debugging, we can use aspectlib to trace execution.

    Define COVERAGE_ASPECTLIB to enable and configure aspectlib to trace
    execution::

        COVERAGE_ASPECTLIB=covaspect.txt:coverage.Coverage:coverage.data.CoverageData program...

    This will trace all the public methods on Coverage and CoverageData,
    writing the information to covaspect.txt.

    """
    aspects = os.environ.get("COVERAGE_ASPECTLIB", "")
    if not aspects:
        return

    import aspectlib                            # pylint: disable=import-error
    import aspectlib.debug                      # pylint: disable=import-error

    class AspectlibOutputFile(object):
        """A file-like object that includes pid and cwd information."""
        def __init__(self, outfile):
            self.outfile = outfile
            self.cwd = None

        def write(self, text):
            """Just like file.write"""
            cwd = os.getcwd()
            if cwd != self.cwd:
                self._write("cwd is now {0!r}\n".format(cwd))
                self.cwd = cwd
            self._write(text)

        def _write(self, text):
            """The raw text-writer, so that we can use it ourselves."""
            self.outfile.write("{0:5d}: {1}".format(os.getpid(), text))

    aspects = aspects.split(':')
    aspects_file = AspectlibOutputFile(open(aspects[0], "a"))
    aspect_log = aspectlib.debug.log(print_to=aspects_file, use_logging=False)
    aspects = aspects[1:]
    public_methods = re.compile(r'^(__init__|[a-zA-Z].*)$')
    for aspect in aspects:
        aspectlib.weave(aspect, aspect_log, methods=public_methods)
