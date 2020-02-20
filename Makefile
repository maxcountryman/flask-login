.PHONY: all test clean_coverage clean pep8 pyflakes check

all:
	@echo 'test           run the unit tests'
	@echo 'coverage       generate coverage statistics'
	@echo 'pep8           check pep8 compliance'
	@echo 'pyflakes       check for unused imports (requires pyflakes)'
	@echo 'check          make sure you are ready to commit'
	@echo 'clean          cleanup the source tree'

test: clean_coverage
	@echo 'Running all tests...'
	coverage run --source=flask_login --module pytest
	coverage report

clean_coverage:
	@rm -f .coverage

clean:
	@rm -f flask_login/*.pyc

pep8:
	@echo 'Checking pep8 compliance...'
	@pycodestyle flask_login/* test_login.py

pyflakes:
	@echo 'Running pyflakes...'
	@pyflakes flask_login/* test_login.py

check: clean pep8 pyflakes test
