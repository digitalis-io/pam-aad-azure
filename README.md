# Dependencies Redhat/Centos

You'll need `epel-release` and `crb` enabled:

```sh
dnf install -y epel-release
dnf config-manager --set-enabled crb
```

Then the following:

```sh
dnf install -y \
    sqlite-devel \
    make gcc \
    autoconf \
    libtool \
    libjwt-devel \
    libcurl-devel \
    pam-devel \
    libuuid-devel \
    openssl-devel \
    jansson-devel \
    diffutils
```

## Compile manually

```sh
make clean
make CFLAGS="-Wall -O2 -DDEBUG=0"
make -C nss clean libnss_aad.so
```

and to install it:

```sh
mkdir -p /lib64/security /etc //var/lib/aad
./libtool   --mode=install /usr/bin/install -c   pam_aad.la /lib64/security
./libtool finish /lib64/security
install -m755 nss/libnss_aad.so.2 /lib64

./create_tables.sh
cp db/* /var/lib/aad
```

## Create RPM

Ensure you have `rpmbuild` installed:

```sh
dnf -y install rpm-build
```

Then run the script:

```sh
./package.sh VERSION
```

Replacing version with the version number of the package.

## Configuration

### Configure Azure Active Directory

1. Create a new `App Registration` in your Azure Active Directory.

   - Set the name to whatever you choose (in this example we will use `pam-aad-oidc`)
   - Set access to `Accounts in this organizational directory only`.
   - Set `Redirect URI` to `Public client/native (mobile & desktop)` with a value of `urn:ietf:wg:oauth:2.0:oob`

2. Under `Certificates & secrets` add a `New client secret`

   - Set the description to `Secret for PAM authentication`
   - Set the expiry time to whatever is relevant for your use-case
   - You must **record the value** of this secret at creation time, as it will not be visible later.

3. Under `API permissions`:
   - Ensure that the following permissions are enabled
      - `Microsoft Graph > User.Read.All` (delegated)
      - `Microsoft Graph > GroupMember.Read.All` (delegated)
   - Select this and click the `Grant admin consent` button (otherwise manual consent is needed from each user)

### Local config

The main configuration is on `/etc/pam_aad.conf`

```json
{
    "client": {
        "id": "{{ pam_oauth_id }}",
        "secret": "{{ pam_oauth_secret }}"
    },
    "domain": "digitalis.io",
    "group": {
        "id": "",
        "name": ""
    },
    "tenant": {
        "name": "{{ tenant_id}}"
    },
    "cache": {
        "root_directory": "/var/lib/aad",
        "owner": "root",
        "group": "root",
        "mode": "0775"
    },
    "home": {
        "directory": "/home",
        "strip_at_sign": true
    }
}
```

Depending on your OS, you'll need to use `pam-auth-update`, `authconfig`, etc to enable the module.