#!/bin/sh

NAME="$1";

if [ -z "$1" ]; then
        echo "$0 <name>";
        exit 3;
fi

numrunning=$(sudo docker ps -q --filter name="$NAME" | wc -l)

if [ "$numrunning" -gt 0 ]; then
        echo "OK";
        exit 0;
else
        echo "No docker process $NAME found";
        echo "CRITICAL";
        exit 2;
fi
