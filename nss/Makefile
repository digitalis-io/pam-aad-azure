libnss_aad.so:
	@rm -f ibnss_aad.so
	gcc -fPIC -shared -lsqlite3 -lssl -lcrypto -o libnss_aad.so -Wl,-soname,libnss_aad.so nss.c

install: libnss_aad.so
	sudo cp libnss_aad.so /lib64
	rm -f libnss_aad.so

all: install