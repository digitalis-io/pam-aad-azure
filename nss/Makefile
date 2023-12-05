clean:
	@rm -f libnss_aad.so*
libnss_aad.so:
	@rm -f libnss_aad.so.2
	# -Werror -Wstrict-prototypes -Wdiscarded-qualifiers
	gcc -Wall -g -fPIC -shared -lsqlite3 -ljansson -lcurl -o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 nss.c cache.c azure.c config.c

install: libnss_aad.so
	sudo cp nsswitch.conf.without-aad /etc/nsswitch.conf
	sudo cp libnss_aad.so.2 /lib64
	sudo ln -fs /lib64/libnss_aad.so.2 /lib64/libnss_aad.so
	rm -f libnss_aad.so
	sudo cp nsswitch.conf.with-aad /etc/nsswitch.conf

all: install

static:
	rm -f /tmp/nss_test
	gcc -DDEBUG=1 -g -lsqlite3 -ljansson -lcurl -lcrypto -lssl -o /tmp/nss_test nss.c cache.c azure.c config.c
