#!/usr/bin/env bash
# Must be run in the root dir of the repo
echo -e "\e[36mBuilding samples\e[39m"
./tools/build_samples.bash
mkdir -p data

export RELEASE_MODE=--release

echo -e "\e[36mBuilding Tool\e[39m"
time cargo build $RELEASE_MODE

mkdir -p ~/.holmes

./tools/chops.sh
./tools/juliet.sh
./tools/bsdcpio.sh
