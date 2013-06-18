import sys
import os


if sys.version_info >= (3, 3):
    requirements = "py3k-requirements.txt"
elif (2, 6) <= sys.version_info < (3, 0):
    requirements = "requirements.txt"
else:
    raise AssertionError("only support 2.6, 2.7, 3.3")


is_dev = sys.argv[1] == "dev" if len(sys.argv) > 1 else False


if __name__ == "__main__":
    if is_dev:
        requirements = "dev-%s" % requirements
    os.system("pip install -r %s --use-mirrors" % requirements)
