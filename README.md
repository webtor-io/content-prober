# content-prober

Wrapper around ffprobe with GRPC access and Redis backend

## Requirements
1. FFmpeg 3+

## Basic usage
```
% ./server help
NAME:
   content-prober-server - runs content prober

USAGE:
   server [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --host value, -H value                 listening host
   --port value, -P value                 listening port (default: 50051)
   --redis-host value, --rH value         hostname of the redis service [$REDIS_MASTER_SERVICE_HOST, $ REDIS_SERVICE_HOST]
   --redis-port value, --rP value         port of the redis service (default: 6379) [$REDIS_MASTER_SERVICE_PORT, $ REDIS_SERVICE_PORT]
   --redis-db value, --rDB value          redis db (default: 0) [$REDIS_DB]
   --redis-password value, --rPASS value  redis password [$REDIS_PASS, $ REDIS_PASSWORD]
   --help, -h                             show help
   --version, -v                          print the version