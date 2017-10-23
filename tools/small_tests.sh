#!/usr/bin/env bash
mkdir -p $HOME/.holmes
./tools/build_samples.bash
cargo build
export BASE_DIR=`mktemp -d`
export HOLMES_PG_SOCK_DIR=`tools/pg.bash $BASE_DIR`
cargo test --test uaf
OUT=$?
rm -rf $BASE_DIR
exit $OUT
