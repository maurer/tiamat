#!/usr/bin/env bash
mkdir -p $HOME/.holmes
export RUST_TEST_THREADS=1
./tools/build_samples.bash
cargo build
export HOLMES_PG_SOCK_DIR=`tools/pg.bash holmes`
cargo test
OUT=$?
rm -rf $HOLMES_PG_SOCK_DIR
exit $OUT
