Name:           pam-aad-azure
Version:        0.0.1
Release:        1%{?dist}
Summary:        Azure PAM and NSS libraries

License:        Apache
URL:            https://github.com/digitalis-io/pam-aad-azure
Source0:        pam-aad-azure-0.0.1.tar.gz

BuildRequires:  sqlite-devel, gcc, libjwt-devel, libcurl-devel
Requires:       libcurl, libjwt, sqlite-libs
%undefine _missing_build_ids_terminate_build

%description
Azure PAM and NSS libraries

%prep
%autosetup


%build
make clean
make CFLAGS=-DDEBUG=0
make -C nss CFLAGS=-DDEBUG=0


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib64/security $RPM_BUILD_ROOT/etc /$RPM_BUILD_ROOT/opt/aad
./libtool   --mode=install /usr/bin/install -c   pam_aad.la $RPM_BUILD_ROOT/lib64/security
rm -f $RPM_BUILD_ROOT/lib64/security/*.la
install -m755 nss/libnss_aad.so.2 $RPM_BUILD_ROOT/lib64
cp db/* $RPM_BUILD_ROOT/opt/aad

%files
/lib64/security/*
/lib64/*
/opt/aad/*.db


%changelog
* Wed Oct 18 2023 Sergio Rua <sergio.rua@digitalis.io>
- First version
