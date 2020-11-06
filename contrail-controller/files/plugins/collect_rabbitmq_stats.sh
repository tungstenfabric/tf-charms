#!/bin/bash
# Copyright (C) 2011, 2014 Canonical
# All Rights Reserved
# Author: Liam Young, Jacek Nykis

RABBIT_PID_PATH=/var/lib/rabbitmq/mnesia/contrail\@${HOSTNAME}-contrail-rmq.pid
RABBIT_PID=$(docker exec configdatabase_rabbitmq_1 cat "$RABBIT_PID_PATH")
if [ "$?" -ne 0 ]; then
    echo "No PID file found"
    exit 1
fi

DATA_DIR="/var/lib/nagios/contrail-controller-rmq"
DATA_FILE="${DATA_DIR}/queue_stats.dat"
LOG_DIR="/var/lib/nagios/contrail-controller-rmq"

if [ ! -d $DATA_DIR ]; then
    mkdir -p $DATA_DIR
fi
if [ ! -d $LOG_DIR ]; then
    mkdir -p $LOG_DIR
fi
TMP_DATA_FILE=$(mktemp -p ${DATA_DIR})
echo "#Vhost Name Messages_ready Messages_unacknowledged Messages Consumers Memory Time" > ${TMP_DATA_FILE}
docker exec configdatabase_rabbitmq_1 /opt/rabbitmq/sbin/rabbitmqctl -q list_vhosts | \
while read VHOST; do
    # "name" VHOST appears to contain column names, skip it
    if [ "$VHOST" = "name" ]; then
        continue;
    fi
    docker exec -t configdatabase_rabbitmq_1 /opt/rabbitmq/sbin/rabbitmqctl -q list_queues -p $VHOST name messages_ready messages_unacknowledged messages consumers memory | \
            awk "\$1 != \"name\" {print \"$VHOST \" \$0 \" $(date +'%s') \"}" 2>${LOG_DIR}/list_queues.log | sed -e 's///g' >> ${TMP_DATA_FILE}
done
mv ${TMP_DATA_FILE} ${DATA_FILE}
chmod 644 ${DATA_FILE}
