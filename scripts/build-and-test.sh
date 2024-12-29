#!/usr/bin/env bash

set -ex

make build
docker compose up -d --build
./scripts/wait-for-it.sh $POSTGRES_HOST:$POSTGRES_PORT -t 30
./scripts/wait-for-it.sh $CLICKHOUSE_HOST:$CLICKHOUSE_PORT -t 30
make migrate
make test
