#!/bin/sh

echo "HTTP_PORT: $HTTP_PORT"
sed -i -e "s/##HTTP_PORT##/${HTTP_PORT}/"  /etc/nginx/conf.d/nginx.conf

echo "DHCP_INTERFACE: $DHCP_INTERFACE"
echo "INTERFACES='${DHCP_INTERFACE}'" >/etc/default/isc-dhcp-server

exec /usr/bin/supervisord
