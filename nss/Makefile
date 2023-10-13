libnss_aad.so:
	@rm -f ibnss_aad.so.2
	# -Werror -Wstrict-prototypes 
	gcc -Wall -fPIC -shared -lsqlite3 -lssl -lcrypto -o libnss_aad.so.2 -Wl,-soname,libnss_aad.so.2 nss.c

install: libnss_aad.so
	sudo cp libnss_aad.so.2 /lib64
	sudo ln -fs /lib64/libnss_aad.so.2 /lib64/libnss_aad.so
	rm -f libnss_aad.so

all: install
