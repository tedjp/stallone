#!/bin/sh
set -ex

libtoolize --force
aclocal
autoconf
autoheader
automake --add-missing --foreign --copy
