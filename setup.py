from setuptools import setup

# Metadata goes in setup.cfg. These are here for GitHub's dependency graph.
setup(
    name="Flask-Login",
    install_requires=[
        "Flask>=1.0.4",
        "Werkzeug>=1.0.1",
    ],
)
