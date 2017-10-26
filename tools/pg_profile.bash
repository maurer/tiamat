#!/usr/bin/env bash
export PGDATA=$1/db
pg_ctl initdb -s -o -Atrust
echo "unix_socket_directories = '$PGDATA'" >> $PGDATA/postgresql.conf
echo "listen_addresses = ''" >> $PGDATA/postgresql.conf
echo "logging_collector = true" >> $PGDATA/postgresql.conf
echo "log_directory = '$PGDATA'" >> $PGDATA/postgresql.conf
echo "shared_preload_libraries = 'auto_explain'" >> $PGDATA/postgresql.conf
echo "auto_explain.log_min_duration = '5s'" >> $PGDATA/postgresql.conf
echo "auto_explain.log_analyze = 'true'" >> $PGDATA/postgresql.conf
echo "synchronous_commit = off" >> $PGDATA/postgresql.conf
echo "wal_level = minimal" >> $PGDATA/postgresql.conf
pg_ctl -w start -s -l/dev/null
createuser -h $PGDATA -s holmes
echo $PGDATA
