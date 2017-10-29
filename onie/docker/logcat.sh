#!/bin/bash
[[ -n "$1" ]] && exec >"$1" 2>&1
exec stdbuf -oL /usr/bin/tail -q -F \
    /var/log/nginx/access.log \
    /var/log/nginx/error.log \
    /var/log/dhcpd.log \
    /var/log/dhcpd.err \
    /var/log/uwsgi.log \
    /var/log/uwsgi.err
