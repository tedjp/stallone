#!/bin/sh
set -ex

aclocal
autoconf
autoheader
automake --add-missing --foreign --copy
