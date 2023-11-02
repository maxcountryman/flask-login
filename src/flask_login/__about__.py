import warnings

warnings.warn(
    "The '__about__' module is deprecated and will be removed in Flask-Login 1.0. Use"
    " 'importlib.metadata' instead.",
    DeprecationWarning,
    stacklevel=2,
)

__title__ = "Flask-Login"
__description__ = "User session management for Flask"
__url__ = "https://github.com/maxcountryman/flask-login"
__version_info__ = ("0", "7", "0")
__version__ = ".".join(__version_info__)
__author__ = "Matthew Frazier"
__author_email__ = "leafstormrush@gmail.com"
__maintainer__ = "Max Countryman"
__license__ = "MIT"
__copyright__ = "(c) 2011 by Matthew Frazier"
