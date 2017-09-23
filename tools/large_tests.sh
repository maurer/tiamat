#!/usr/bin/env bash
# Must be run in the root dir of the repo
echo -e "\e[36mBuilding samples\e[39m"
./tools/build_samples.bash

RELEASE_MODE=--release

echo -e "\e[36mBuilding Tool\e[39m"
time cargo build $RELEASE_MODE

LARGE_OUT=large_tests_out
rm -rf $LARGE_OUT
mkdir -p $LARGE_OUT

mkdir -p ~/.holmes

echo -e "\e[36mTesting Juliet Sample CWE416\e[39m"
export TIAMAT_PG_SOCK_DIR=`./tools/pg.bash`
export RUST_LOG=tiamat=info
if time cargo run $RELEASE_MODE --bin uaf -- -i samples/Juliet/testcases/CWE416_Use_After_Free/CWE416 > $LARGE_OUT/CWE416.out 2> $LARGE_OUT/CWE416.err; then
	echo -e "\e[32mAnalysis Completed\e[39m"
	if diff $LARGE_OUT/CWE416.out ./test_outputs/CWE416 ; then
		echo -e "\e[32mNo Change\e[39m"
	else
		echo -e "\e[93mDetection rates have changed! Please examine the output. If it is an improvement, update the reference file.\e[39m"
	fi
else
	echo -e "\e[91mAnalysis Failed\nPlease examine $LARGE_OUT/CWE416.err for more details\e[39m"
fi

mv *.html $LARGE_OUT
mv *.hprof $LARGE_OUT

rm -rf $TIAMAT_PG_SOCK_DIR
