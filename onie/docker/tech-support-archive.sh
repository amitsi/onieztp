#!/bin/bash

TMPDIR=$( mktemp -d )
trap 'rm -rf "$TMPDIR"' EXIT

cd "$TMPDIR"

BUNDLEID="unum-ztp-tech-support-bundle-$( date +'%Y-%m-%d-%H%M' )-$RANDOM"
BUNDLEDIR="${TMPDIR}/${BUNDLEID}"
ARCHDIR="/ztpvol/html/images/tech-support-bundles"

if [[ -d "$1" ]]; then
    ARCHDIR="$1"
fi

mkdir "$BUNDLEDIR"

cd "$BUNDLEDIR"
mkdir logs
cd logs
cp  /var/log/nginx/access.log nginx-access.log
cp  /var/log/nginx/error.log nginx-error.log
cp  /var/log/dhcpd.log \
    /var/log/dhcpd.err \
    /var/log/uwsgi.log \
    /var/log/uwsgi.err \
    /var/log/supervisord.log \
    .
cp  -r /var/log/supervisor .

cd "$BUNDLEDIR"
cp /ztpvol/onie.db .

cd /ztpvol/html

IMAGESLIST="$TMPDIR/images.list"
find images \( -type f -o -type l \) | sort >"$IMAGESLIST"

if [[ -s "$IMAGESLIST" ]]; then
    for TYPE in sha1 md5; do
        cat "$IMAGESLIST" | xargs ${TYPE}sum >>"${BUNDLEDIR}/images.${TYPE}"
    done
fi

cd "$BUNDLEDIR"
cp -r /var/lib/dhcp .

cd "$BUNDLEDIR"
[[ -f /var/log/tshark.log ]] && cp /var/log/tshark.log .

cd "$TMPDIR"

mkdir -p "$ARCHDIR"
ARCHIVE="$ARCHDIR/${BUNDLEID}.tar"

tar cf "$ARCHIVE" "$BUNDLEID"
bzip2 "$ARCHIVE"

ZIPARCHIVE="${ARCHIVE}.bz2"
[[ -f "$ZIPARCHIVE" ]] && echo ARCHIVE=$( basename "$ZIPARCHIVE" )
