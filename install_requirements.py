import sys
import os


is_dev = sys.argv[1] == "dev" if len(sys.argv) > 1 else False


if sys.version_info >= (3, 5):
    requirements = "requirements.txt"
elif sys.version_info[:2] == (2, 7):
    if is_dev:
        requirements = "py2-requirements.txt"
    else:
        requirements = "requirements.txt"
else:
    raise AssertionError("only support 2.7")


if __name__ == "__main__":
    if is_dev:
        requirements = "dev-%s" % requirements
    os.system("pip install -r %s" % requirements)
