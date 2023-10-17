libnss_aad.so:
	@rm -f ibnss_aad.so.2
	# -Werror -Wstrict-prototypes 
	gcc -Wall -fPIC -shared -lsqlite3 -lssl -lcrypto -ljansson -o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 nss.c cache.c

install: libnss_aad.so
	sudo cp nsswitch.conf.without-aad /etc/nsswitch.conf
	sudo cp libnss_aad.so.2 /lib64
	sudo ln -fs /lib64/libnss_aad.so.2 /lib64/libnss_aad.so
	rm -f libnss_aad.so
	sudo cp nsswitch.conf.with-aad /etc/nsswitch.conf

all: install
