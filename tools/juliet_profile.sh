#!/usr/bin/env bash
# Must be run in the root dir of the repo

LARGE_OUT=$PWD/data/juliet_profile
rm -rf $LARGE_OUT
mkdir -p $LARGE_OUT

mkdir -p ~/.holmes

export TIAMAT_PG_SOCK_DIR=`./tools/pg_profile.bash $LARGE_OUT`
export RUST_LOG=tiamat=debug,holmes=trace
cargo build --release
time perf record ./target/release/uaf -t 30 -i samples/Juliet/testcases/CWE416_Use_After_Free/CWE416 > $LARGE_OUT/out 2> $LARGE_OUT/err
mv *.hprof $LARGE_OUT
