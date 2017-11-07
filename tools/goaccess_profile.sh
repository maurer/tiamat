#!/usr/bin/env bash
# Must be run in the root dir of the repo

LARGE_OUT=$PWD/data/goaccess
rm -rf $LARGE_OUT
mkdir -p $LARGE_OUT

mkdir -p ~/.holmes

export PGDATA=$LARGE_OUT/db
export TIAMAT_PG_SOCK_DIR=`./tools/pg_profile.bash $LARGE_OUT`
export RUST_LOG=tiamat=debug,holmes=trace
cargo build --release
./target/release/uaf -t 30 -i samples/whole/goaccess > $LARGE_OUT/out 2> $LARGE_OUT/err
mv *.hprof $LARGE_OUT
