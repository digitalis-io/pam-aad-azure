#!/bin/bash

VERSION=${1:-0.0.2}

make clean
make -C nss clean
mkdir -p /tmp/pam-aad-azure-${VERSION}
cp -a * /tmp/pam-aad-azure-${VERSION}/
mkdir -p /tmp/pam-aad-azure-${VERSION}/db
sudo cp -a /opt/aad/*.db /tmp/pam-aad-azure-${VERSION}/db
sudo chown -R $USER:$USER /tmp/pam-aad-azure-${VERSION}/db
(cd /tmp && tar zcpf pam-aad-azure-${VERSION}.tar.gz pam-aad-azure-${VERSION})
mv /tmp/pam-aad-azure-${VERSION}.tar.gz ~/rpmbuild/SOURCES

rpmbuild -ba ~/rpmbuild/SPECS/pam-aad-azure.spec
