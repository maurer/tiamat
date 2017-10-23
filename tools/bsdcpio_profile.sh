#!/usr/bin/env bash
# Must be run in the root dir of the repo

LARGE_OUT=$PWD/data/bsdcpio_test_profile
rm -rf $LARGE_OUT
mkdir -p $LARGE_OUT

mkdir -p ~/.holmes

export TIAMAT_PG_SOCK_DIR=`./tools/pg_profile.bash $LARGE_OUT`
export RUST_LOG=tiamat=info
# Time out in 1 hr
TIMEOUT=3600
cargo build --release
time perf record ./target/release/uaf -l $TIMEOUT -i samples/whole/bsdcpio_test > $LARGE_OUT/out 2> $LARGE_OUT/err
mv *.hprof $LARGE_OUT
mv perf.data $LARGE_OUT
