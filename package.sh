#!/bin/bash

VERSION=${1:-0.0.2}

make clean
make -C nss clean
mkdir -p /tmp/pam-aad-azure-${VERSION}
cp -a * /tmp/pam-aad-azure-${VERSION}/
(cd /tmp && tar zcpf pam-aad-azure-${VERSION}.tar.gz pam-aad-azure-${VERSION})
mv /tmp/pam-aad-azure-${VERSION}.tar.gz ~/rpmbuild/SOURCES
