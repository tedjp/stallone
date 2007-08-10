#!/bin/sh
set -ex

autoconf
aclocal
autoheader
automake --add-missing --foreign --copy
