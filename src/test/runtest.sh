#!/bin/bash

set -x

testdir=`dirname $0`

. $testdir/funcs

test_numpass=0

for t in $testdir/t.*; do
    bash -c ". $testdir/funcs; . $t" && success $t || fail $t
done
