#!/usr/bin/env bash
export PGDATA=`mktemp -d` #`mktemp -d .tmp.XXXXXX -p $PWD`
pg_ctl initdb -s -o -Atrust
echo "unix_socket_directories = '$PGDATA'" >> $PGDATA/postgresql.conf
echo "listen_addresses = ''" >> $PGDATA/postgresql.conf
echo "synchronous_commit = off" >> $PGDATA/postgresql.conf
echo "fsync = off" >> $PGDATA/postgresql.conf
echo "wal_level = minimal" >> $PGDATA/postgresql.conf
pg_ctl -w start -s -l/dev/null
createuser -h $PGDATA -s holmes
echo $PGDATA
