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

from nose.plugins import Plugin

from yanc.colorstream import ColorStream


class YancPlugin(Plugin):
    """Yet another nose colorer"""

    name = "yanc"

    def options(self, parser, env):
        super(YancPlugin, self).options(parser, env)
        parser.add_option(
            "--yanc-color",
            action="store",
            dest="yanc_color",
            default=env.get("NOSE_YANC_COLOR"),
            help="YANC color override - one of on,off [NOSE_YANC_COLOR]",
        )

    def configure(self, options, conf):
        super(YancPlugin, self).configure(options, conf)
        if options.yanc_color is None and not conf.worker \
                and hasattr(conf.stream, "isatty") and conf.stream.isatty():
            # if color is not set then set color on the basis of the stream's
            # tty status - this is set on options so that the value is
            # propagated to multiprocess workers meaning that the option is
            # never None when conf.worker is True
            # XXX: apparently not, see #6
            options.yanc_color = "on"
        self.color = options.yanc_color != "off"

    def setOutputStream(self, stream):
        # when run in series, this method gets called once and that is enough,
        # when run in parallel, this method is called at the top level which
        # deals with the test summary information but the workers need
        # prepareTestResult to have their output colored
        return self.color and ColorStream(stream) or stream

    def prepareTestResult(self, result):
        if not isinstance(result.stream, ColorStream):
            result.stream = self.setOutputStream(result.stream)
