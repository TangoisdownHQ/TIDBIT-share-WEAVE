#!/bin/sh
set -eu

echo "wrapper: starting TIDBIT container bootstrap"
echo "wrapper: user=$(id -u):$(id -g)"
echo "wrapper: pwd=$(pwd)"
echo "wrapper: PORT=${PORT:-unset}"

if [ ! -x /usr/local/bin/tidbit ]; then
  echo "wrapper: binary missing or not executable at /usr/local/bin/tidbit"
  ls -l /usr/local/bin || true
  exit 127
fi

echo "wrapper: tidbit binary present"
ls -l /usr/local/bin/tidbit || true
echo "wrapper: web dir contents"
ls -la /app/backend-rs/web | sed -n '1,10p' || true
echo "wrapper: launching server"

exec /usr/local/bin/tidbit server
