#!/bin/bash

# set -x

target=$1
testdir=$(cd $(dirname $0); pwd -P)
tmpdir=`mktemp -d`

export target testdir tmpdir

trap "rm -rf $tmpdir" QUIT EXIT INT HUP

. $testdir/funcs

begin

for s in $testdir/t.*; do
    t=$(basename $s)
    r=$tmpdir/results.$$.$t
    export result=$r
    out=$tmpdir/out.$$.$t
    echo "=== $t ==="
    bash -c "exec 99>$r; . $testdir/setup; . $s" 2>$out && win $t || lose $t $?
done

finish
