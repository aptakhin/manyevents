#!/usr/bin/env bash

set -ex

if [ -z "$1" ]; then
    echo "Error: No release directory name provided."
    echo "Usage: $0 <release-directory-name>"
    exit 1
fi

make build-release

BASE_TMP=`mktemp -d`
RELEASE_DIR=$BASE_TMP/$1
mkdir -p $RELEASE_DIR
cp -r manyevents/static $RELEASE_DIR
cp -r manyevents/target/release/manyevents $RELEASE_DIR
tar -czvf $1.tar.gz -C $BASE_TMP $1
