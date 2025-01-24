@echo off
set RABBIT_ADDRESSES=localhost:5672
set STORAGE_TYPE=mysql
set MYSQL_USER=zipkin
set MYSQL_PASS=zipkin
set MYSQL_TCP_PORT=33060
java -jar ./zipkin-server-3.4.1-exec.jar