#!/bin/bash
# The script is needed to run Contrail Command deploy in virtualenv
# to prevent issues with installed librarys

run_deploy=$1

rm -rf /tmp/venv
virtualenv /tmp/venv
source /tmp/venv/bin/activate

apt-get install -y python-pip
pip install "ansible==2.7.11"

export HOME=/root

$run_deploy
