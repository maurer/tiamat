#!/usr/bin/env bash
psql postgres -h /anvil/data/$1 -c 'drop database holmes'
