# Sample bundle with additions of Octavia to deploy with Contrail+OpenStack

This readme was prepared for Ubuntu 18.04. To deploy it in Ubuntu 20.04 please use innodb instead of mysql/percona.
Prepare Juju setup with openstack Train and octavia overlay bundle:

```bash
juju deploy --overlay=./octavia-bundle.yaml ./bundle.yaml
```

or you can add octavia in a same way after deployment of main bundle:

```bash
juju deploy --overlay=./octavia-bundle.yaml --map-machines=existing ./bundle.yaml
```

Please note - if you have network bindings in main bundle file then you have to replicate it to octavia’s bundle.
If you want to ssh into Amphora instances later for debug purposes then please prepare a ssh key before deployment and add the content into octavia-bundle.yaml

```bash
ssh-keygen -f octavia # generate the key
base64 octavia.pub # print public key data
```

Then next options should be added to octavia options:
amp-ssh-pub-key: # paste public key data here
amp-ssh-key-name: octavia

used documents:
<https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/train/app-octavia.html>
<https://github.com/openstack-charmers/openstack-bundles/blob/master/stable/overlays/loadbalancer-octavia.yaml>

After configurinng all certs, vault, amphora image you need to configure network.
Please source creds for openstack CLI and install python-openstackclient and python-octaviaclient (in virtualenv) (or use Horizon UI).

Create mgmt network for octavia (please note that these object must be created in ‘services’ project):

```bash
project=$(openstack project list --domain service_domain | awk '/services/{print $2}')
openstack network create octavia --tag charm-octavia --project $project
openstack subnet create --subnet-range 172.24.0.0/24 --network octavia --tag charm-octavia octavia
# security group for octavia
openstack security group create octavia --tag charm-octavia --project $project
openstack security group rule create --ingress --ethertype IPv4 --protocol icmp octavia
openstack security group rule create --ingress --ethertype IPv6 --protocol icmp octavia
openstack security group rule create --ingress --ethertype IPv4 --protocol tcp --dst-port 22:22 octavia
openstack security group rule create --ingress --ethertype IPv6 --protocol tcp --dst-port 22:22 octavia
openstack security group rule create --ingress --ethertype IPv6 --protocol tcp --dst-port 9443:9443 octavia
openstack security group rule create --ingress --ethertype IPv4 --protocol tcp --dst-port 9443:9443 octavia
# security group for octavia-health
openstack security group create octavia-health --tag charm-octavia-health --project $project
openstack security group rule create --ingress --ethertype IPv4 --protocol icmp octavia-health
openstack security group rule create --ingress --ethertype IPv6 --protocol icmp octavia-health
openstack security group rule create --ingress --ethertype IPv4 --protocol udp --dst-port 5555:5555 octavia-health
openstack security group rule create --ingress --ethertype IPv6 --protocol udp --dst-port 5555:5555 octavia-health
```

Then please create policy and attach it to this network inWebUI.
Next you need to configure IP Fabric Forwarding for this network in WebUI also.

And finally configure octavia with created network:

```bash
juju run-action --wait octavia/leader configure-resources
```

After this command juju cluster should fully functional and all units should be active.

How to create routes from fabric network to Amphora VM-s please read in latest Juniper's documentation.
