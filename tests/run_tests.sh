#!/bin/sh

cd $(dirname $0)

# Make sure pytest is installed.
export PYTEST_SESSION=1
pytest --version  >/dev/null 2>&1 || (echo "pytest (https://docs.pytest.org/en/latest/getting-started.html) must be installed"; exit 1)

PYTHONPATH=.. pytest $*
