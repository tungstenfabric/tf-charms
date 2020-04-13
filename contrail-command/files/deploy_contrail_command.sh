#!/bin/bash
# The script is needed to run Contrail Command deploy in virtualenv
# to prevent issues with installed librarys

import=$1

rm -rf /tmp/venv
virtualenv /tmp/venv
source /tmp/venv/bin/activate

export HOME=/root
if [ -n "$import" ] ; then
    source /tmp/juju_environment
else
    apt install -y python-pip
    pip install "ansible==2.7.11"
    export HOME=/root
fi
/contrail-command-deployer/docker/deploy_contrail_command
