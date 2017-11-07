#!/usr/bin/env bash
export PGDATA=$1/db
pg_ctl initdb -s -o -Atrust
echo "unix_socket_directories = '$PGDATA'" >> $PGDATA/postgresql.conf
echo "listen_addresses = ''" >> $PGDATA/postgresql.conf
echo "synchronous_commit = off" >> $PGDATA/postgresql.conf
echo "fsync = off" >> $PGDATA/postgresql.conf
echo "wal_level = minimal" >> $PGDATA/postgresql.conf
echo "max_connections = 1000" >> $PGDATA/postgresql.conf
pg_ctl -w start -s -l/dev/null
createuser -h $PGDATA -s holmes
echo $PGDATA
