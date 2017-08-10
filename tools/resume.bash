#!/usr/bin/env bash
export PGDATA=$TIAMAT_PG_SOCK_DIR
pg_ctl -w start -s -l/dev/null
