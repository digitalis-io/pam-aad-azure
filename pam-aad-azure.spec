Name:           pam-aad-azure
Version:        %VERSION%
Release:        1%{?dist}
Summary:        Azure PAM and NSS libraries

License:        Apache
URL:            https://github.com/digitalis-io/pam-aad-azure
Source0:        pam-aad-azure-%{version}.tar.gz

BuildRequires:  sqlite-devel, gcc, libjwt-devel, libcurl-devel, openssl-devel, libuuid-devel, pam-devel
Requires:       libcurl, libjwt, sqlite-libs, jansson
%undefine _missing_build_ids_terminate_build

%description
Azure PAM and NSS libraries

%prep
%autosetup

%configure --with-pam-dir=/lib64/security

%build
make clean
make
make -C nss clean libnss_aad.so

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/lib64/security $RPM_BUILD_ROOT/etc /$RPM_BUILD_ROOT/var/lib/aad
./libtool   --mode=install /usr/bin/install -c   pam_aad.la $RPM_BUILD_ROOT/lib64/security
./libtool finish $RPM_BUILD_ROOT/lib64/security
install -m755 nss/libnss_aad.so.2 $RPM_BUILD_ROOT/lib64
cp db/* $RPM_BUILD_ROOT/var/lib/aad

%files
%attr(0755, root, root) /lib64/security/*aad*
%attr(0755, root, root) /lib64/*aad*
%attr(0775, root, postgres) /var/lib/aad
%attr(0664, root, postgres) /var/lib/aad/*.db

%changelog
* Mon Nov 06 2023 Sergio Rua <sergio.rua@digitalis.io> 0.0.5-2
- Move cache to /var/lib/aad
* Mon Nov 06 2023 Sergio Rua <sergio.rua@digitalis.io> 0.0.5-1
- Bug fixes and updates
* Wed Oct 18 2023 Sergio Rua <sergio.rua@digitalis.io> 0.0.4-1
- First version
