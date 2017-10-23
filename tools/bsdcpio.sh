#!/usr/bin/env bash
# Must be run in the root dir of the repo

LARGE_OUT=$PWD/data/bsdcpio_test
rm -rf $LARGE_OUT
mkdir -p $LARGE_OUT

mkdir -p ~/.holmes

export TIAMAT_PG_SOCK_DIR=`./tools/pg.bash $LARGE_OUT`
export RUST_LOG=tiamat=info
cargo run $RELEASE_MODE --bin uaf -t 30 -i samples/whole/bsdcpio_test > $LARGE_OUT/out 2> $LARGE_OUT/err
mv *.hprof $LARGE_OUT
