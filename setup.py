from setuptools import setup

# Metadata goes in setup.cfg. These are here for GitHub's dependency graph.
setup(
    name="Flask-Login",
    install_requires=[
        "Flask>=2.2.5",
        "Werkzeug>=2.2.3",
    ],
)
