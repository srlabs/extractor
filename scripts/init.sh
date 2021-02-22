#!/usr/bin/env bash

set -e

pushd () {
	command pushd "$@" > /dev/null
}

popd () {
	command popd "$@" > /dev/null
}

echo "*** Initializing Extractor build environment"

# Init git submodule
git submodule update --init

PROJECT_ROOT=`git rev-parse --show-toplevel`

# Save current directory.
pushd .

cd $PROJECT_ROOT/sinextract
make

# Restore initial directory.
popd
