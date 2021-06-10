#!/bin/bash -e
# The script is needed to run Contrail Command deploy in virtualenv
# to prevent issues with installed librarys

apt-get install -y python3-pip python3-virtualenv

rm -rf /tmp/venv
python3 -m virtualenv --python=python3 /tmp/venv
source /tmp/venv/bin/activate

python3 -m pip install "ansible==2.9.7" six

export HOME=/root

$@
