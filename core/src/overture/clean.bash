#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DEPS=$DIR/dependencies

rm -rf $DEPS
rm -rf $DIR/go/bin
rm -rf $DIR/bin
rm -rf $DIR/pkg
rm -rf $DIR/src/golang.org

echo "Successfully clean overture"
