#!/usr/bin/env bash
set -x
set -eo pipefail

# if a redis container is running, print instructions to kill it and exit
RUNNING_CONTAINER=$(docker ps --filter 'name=redis' --format '{{.ID}}')
if [[ -n $RUNNING_CONTAINER ]]; then
	echo >&2 "there is a redis container already running, kill it with"
	echo >&2 "    docker kill ${RUNNING_CONTAINER}"
	exit 1
fi

# Launch Redis using Docker
docker run \
	-p "6379:6379" \
	-p "8001:8001" \
	-d \
	--name "redis_stack_$(date '+%s')" \
	redis/redis-stack:latest

>&2 echo "Redis Stack is ready!"
>&2 echo "Dashboard available at: http://localhost:8001"
