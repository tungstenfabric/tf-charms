#!/bin/sh

MODULE_NAME="vrouter"

kernelrel=$(uname -r)
modpath=$(modinfo -n "$MODULE_NAME")
modkernrel=$(modinfo -F vermagic "$modpath" | awk '{print $1}')

if [ "$kernelrel" = "$modkernrel" ]; then
    echo "OK";
    exit 0;
else
    echo "CRITICAL";
    exit 2;
fi

