#!/bin/bash

HOST=${APP_HOST:="0.0.0.0"}
PORT=${APP_PORT:="8080"}

echo 'start tiny-rp'
exec uvicorn main:app --host $HOST --port $PORT
