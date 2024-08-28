#!/bin/bash

if [ -f '/mnt/certs/iam/ca.crt' ]
then
    cd / && exec /usr/bin/python -m keycloak_client "$@"
else
    echo "ERROR: /mnt/certs/iam/ca.crt does not exist"
    echo "Please mount the signing CA certificate(s) of keycloak's server certificate to /mnt/certs/iam/ca.crt location of the container."
    exit 1
fi