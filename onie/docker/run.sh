#!/bin/sh

echo "HTTP_PORT: $HTTP_PORT"
sed -i -e "s/##HTTP_PORT##/${HTTP_PORT}/"  /etc/nginx/conf.d/nginx.conf

exec /usr/bin/supervisord
