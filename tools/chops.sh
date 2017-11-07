#!/usr/bin/env bash
# Must be run in the root dir of the repo
CHOP_OUT=$PWD/data/chops
mkdir -p $CHOP_OUT
export HOLMES_PG_SOCK_DIR=`./tools/pg.bash $CHOP_OUT`
if time cargo test --release --test chops -- --nocapture | tee $CHOP_OUT/out; then
	echo -e "\e[32All Chops Validated\e[39m"
else
	echo -e "\e[32Some chops failed to validate\nPlease examine $CHOP_OUT for more details\e[39m"
	echo -e "\e[91mDatabase has been kept at $HOLMES_PG_SOCK_DIR for examination\e[39m"
fi
