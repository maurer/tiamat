#!/usr/bin/env bash
mkdir -p $HOME/.holmes
./tools/build_samples.bash
cargo build
export HOLMES_PG_SOCK_DIR=`tools/pg.bash holmes`
cargo test
OUT=$?
rm -rf $HOLMES_PG_SOCK_DIR
exit $OUT
