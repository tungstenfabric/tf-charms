# check-charm-version
Compare the commit hashes of Contrail charm versions to infer compatibility based on whether or not they were committed at the same time

```
usage: check-charm-versions.py [-h]
                               agent analytics analyticsdb controller keystone
                               openstack

compare charm commit hashes

positional arguments:
  agent        contrail-agent charm version
  analytics    contrail-analytics charm version
  analyticsdb  contrail-analyticsdb charm version
  controller   contrail-controller charm version
  keystone     contrail-keystone-auth charm version
  openstack    contrail-openstack charm version

optional arguments:
  -h, --help   show this help message and exit
```

For example:
```
python check-charm-versions.py contrail-agent-18 contrail-analytics-16 contrail-analyticsdb-16 \
                               contrail-controller-17 contrail-keystone-auth-16 contrail-openstack-19
Or
python check-charm-versions.py `juju export-bundle | grep juniper-os-software |awk -F \/ '{print $2}' | xargs`
```
