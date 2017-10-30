#!/bin/bash

while :; do
    flask nvos_status --quiet
    sleep 60
done
