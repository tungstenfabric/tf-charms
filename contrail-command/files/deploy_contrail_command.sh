#!/bin/bash -e
# The script is needed to run Contrail Command deploy in virtualenv
# to prevent issues with installed libraries

if [ -f /etc/default/locale ]; then
  # if system has locale then we have to export it to pip run below
  # otherwise 'pip install' may fail on non-ascii chars
  set -o allexport
  source /etc/default/locale || /bin/true
  set +o allexport
fi

apt-get install -y python3-pip python3-virtualenv

rm -rf /tmp/venv
python3 -m virtualenv --python=python3 /tmp/venv
source /tmp/venv/bin/activate

python3 -m pip install "ansible==2.9.7" six

export HOME=/root
export orchestrator=juju

$@
