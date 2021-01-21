Overview
--------

OpenContrail (www.opencontrail.org) is a fully featured Software Defined
Networking (SDN) solution for private clouds. It supports high performance
isolated tenant networks without requiring external hardware support.

This charm is designed to be used in conjunction with the rest of the OpenStack
related charms in the charm store and specially with Ironic charms to handle
baremetal provisioning with Contrail.

Usage
-----

Deploy it and relate to other ends.

    juju deploy contrail-openstack-ironic
    juju add-relation contrail-controller contrail-openstack-ironic
    juju add-relation contrail-openstack-ironic rabbitmq-server

External Docker repository
--------------------------

Istead of attaching resource with docker image charm can accept image from remote docker repository.
docker-registry should be specified if the registry is only accessible via http protocol (insecure registry).
docker-user / docker-password can be specified if registry requires authentification.
And image-name / image-tag are the parameters for the image itself.

SSL
---

This charm supports relation to easyrsa charm to obtain certificates for XMPP and Sandesh connections:

    juju add-relation contrail-openstack-ironic easyrsa

Please note that in this case all charms must be related to easyrsa. Components require CA certificate for communication.
