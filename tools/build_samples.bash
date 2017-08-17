#!/usr/bin/env bash

# "bindnow" prevents most PLT generation, and -O2 (implied by some other hardenings)
# can optimize out code in my simplistic examples
export hardeningDisable="all";

make -j9 -C samples/Juliet/testcases/CWE416_Use_After_Free/
make -j9 -C samples/use_after_free
