#!/bin/bash

OUTFILE=/var/log/tshark.log
DHCP_INTF_FILE=/var/run/dhcp_interface

DHCP_INTF=$( head -n 1 "$DHCP_INTF_FILE" 2>/dev/null )
if [[ -z "$DHCP_INTF" ]]; then
    echo "DHCP Interface not found; unable to start tshark" >&2
    exit 2
fi

echo "Starting tshark on interface $DHCP_INTF"

cleanup() {
    while pgrep -x tshark >/dev/null 2>&1; do
        pkill -x tshark
        sleep 1
    done
    echo "[END] $(date)" >>"$OUTFILE"
}

echo "[START] $(date)" >"$OUTFILE"
trap 'cleanup' EXIT

stdbuf -oL tshark -i "$DHCP_INTF" -f "udp port 67 or port 68" \
	-o 'gui.column.format:"No.","%m","Time","%t","MAC","%uhs","Source","%s","Destination","%d","Protocol","%p","Length","%L","Info","%i"' \
	>>"$OUTFILE"
