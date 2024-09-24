#!/bin/bash

VERSION=${1:-0.1.0}

./create_tables.sh

make clean
make -C nss clean
rm -rf /tmp/pam-aad-azure-${VERSION}
mkdir -p /tmp/pam-aad-azure-${VERSION}
cp -a * /tmp/pam-aad-azure-${VERSION}/
mkdir -p /tmp/pam-aad-azure-${VERSION}/db
(cd /tmp && tar zcpf pam-aad-azure-${VERSION}.tar.gz pam-aad-azure-${VERSION})
rm -f ~/rpmbuild/SOURCES/pam*
mv /tmp/pam-aad-azure-${VERSION}.tar.gz ~/rpmbuild/SOURCES

mkdir -p ~/rpmbuild/{SPECS,SOURCES}
cp pam-aad-azure.spec ~/rpmbuild/SPECS
sed -i "s/%VERSION%/${VERSION}/g" ~/rpmbuild/SPECS/pam-aad-azure.spec

rm -f ~/rpmbuild/RPMS/x86_64/pam-aad-azure*rpm
rpmbuild -ba ~/rpmbuild/SPECS/pam-aad-azure.spec

rm -rf /tmp/pam-aad*

