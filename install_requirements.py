import sys
import os


is_dev = sys.argv[1] == "dev" if len(sys.argv) > 1 else False


if sys.version_info >= (3, 3):
    requirements = "requirements.txt"
elif (2, 6) <= sys.version_info < (3, 0):
    if is_dev:
        requirements = "py2-requirements.txt"
    else:
        requirements = "requirements.txt"
else:
    raise AssertionError("only support 2.6, 2.7, 3.3")


if __name__ == "__main__":
    if is_dev:
        requirements = "dev-%s" % requirements
    os.system("pip install -r %s" % requirements)
