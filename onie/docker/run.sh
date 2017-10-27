#!/bin/sh

echo "HTTP_PORT: $HTTP_PORT"
echo "HTTPS_PORT: $HTTPS_PORT"
sed -i -e "s/##HTTP_PORT##/${HTTP_PORT}/" \
       -e "s/##HTTPS_PORT##/${HTTPS_PORT}/" /etc/nginx/conf.d/nginx.conf

echo "DHCP_INTERFACE: $DHCP_INTERFACE"
echo "INTERFACES='${DHCP_INTERFACE}'" >/etc/default/isc-dhcp-server

INITDB_FLAG='/ztpvol/initdb'

if [ -e "$INITDB_FLAG" ]; then
    rm -f "$INITDB_FLAG"
else
    echo "Upgrading database schema"
    (cd /app/onie && FLASK_APP=onie flask db upgrade)
fi

exec /usr/bin/supervisord
