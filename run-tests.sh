#!/bin/bash

OUTPUT_PATH=$(pwd)/tests_output

function log() {
    echo "$@" | tee -a $OUTPUT_PATH/test.log
}

rm -rf $OUTPUT_PATH
mkdir -p $OUTPUT_PATH

NOSETEST_OPTIONS="-d"

if [ -n "$VERBOSE" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --verbose"
fi

if [ -z "$NOCOLOR" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --with-yanc --yanc-color=on"
fi

if [ -n "$OPTIONS" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS $OPTIONS"
fi

if [ -n "$TESTS" ]; then
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS $TESTS"
else
    NOSETEST_OPTIONS="$NOSETEST_OPTIONS --with-coverage --cover-min-percentage=100 --cover-package=flask_login"
fi

log "Running tests..."
nosetests $NOSETEST_OPTIONS 2>&1 | tee -a $OUTPUT_PATH/test.log
ret=${PIPESTATUS[0]}

echo

case "$ret" in
    0) log -e "SUCCESS" ;;
    *) log -e "FAILURE" ;;
esac

exit $ret
