#!/usr/bin/env bash
psql postgres -U holmes -c 'drop database holmes'
psql postgres -U holmes -c 'create database holmes'
