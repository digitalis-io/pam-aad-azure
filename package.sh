#!/bin/bash

VERSION=${1:-0.0.7}

make clean
make -C nss clean
rm -rf /tmp/pam-aad-azure-${VERSION}
mkdir -p /tmp/pam-aad-azure-${VERSION}
cp -a * /tmp/pam-aad-azure-${VERSION}/
mkdir -p /tmp/pam-aad-azure-${VERSION}/db
sudo cp -a /opt/aad/*.db /tmp/pam-aad-azure-${VERSION}/db
sudo chown -R $USER:$USER /tmp/pam-aad-azure-${VERSION}/db
(cd /tmp && tar zcpf pam-aad-azure-${VERSION}.tar.gz pam-aad-azure-${VERSION})
rm -f ~/rpmbuild/SOURCES/pam*
mv /tmp/pam-aad-azure-${VERSION}.tar.gz ~/rpmbuild/SOURCES

cp pam-aad-azure.spec ~/rpmbuild/SPECS
sed -i "s/%VERSION%/${VERSION}/g" ~/rpmbuild/SPECS/pam-aad-azure.spec

rm -f /home/sergio.rua/rpmbuild/RPMS/x86_64/pam-aad-azure*rpm
rpmbuild -ba ~/rpmbuild/SPECS/pam-aad-azure.spec

rm -rf /tmp/pam-aad*

aws s3 cp /home/sergio.rua/rpmbuild/RPMS/x86_64/pam-aad-azure-${VERSION}-*.el9.x86_64.rpm s3://mgmt-mgmt-tokenise-postgres/
