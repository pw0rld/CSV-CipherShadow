# gmssl path
LIBDIR = /opt/gmssl/lib/
INCDIR = /opt/gmssl/include/
ATTESTATION_DIR := ./
CSV_SDK_DIR := $(ATTESTATION_DIR)/csv_sdk
CSV_CIPHER_DIR := $(ATTESTATION_DIR)/csv_cipher

all: dynamic_csv_sdk static_csv_sdk vmmcall-get-attestation  ioctl-get-attestation  verify-attestation get_key ioctl_get_key calc-vm-digest

CFLAGS := -I$(INCDIR) -I$(ATTESTATION_DIR) -L$(LIBDIR) -m64 -mrdrnd -DLOG_ON
STATIC_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bstatic
SHARED_CFLAGS := -Wl,-rpath,$(LIBDIR),-Bdynamic

dynamic_csv_sdk:
	gcc -Wall $(CFLAGS) -c -fpic csv_sdk/*.c
	gcc -Wall $(CFLAGS) -o libcsv.so -shared *.o $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
	rm *.o

static_csv_sdk:
	gcc -Wall $(CFLAGS) -c csv_sdk/*.c
	ar -r libcsv.a *.o
	rm *.o

vmmcall-get-attestation: vmmcall_get_attestation.c
	gcc -Wall $(CFLAGS) -o vmmcall-get-attestation vmmcall_get_attestation.c -L. libcsv.a $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread
	cp vmmcall-get-attestation get-attestation

ioctl-get-attestation: ioctl_get_attestation.c
	gcc -Wall $(CFLAGS) -o ioctl-get-attestation ioctl_get_attestation.c -L. libcsv.a $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

verify-attestation: verify_attestation.c
	gcc -Wall $(CFLAGS) -o verify-attestation verify_attestation.c -L. libcsv.a $(SHARED_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

get_key: vmmcall_get_key.c
	gcc -Wall $(CFLAGS) -o get_key vmmcall_get_key.c -L. libcsv.a $(STATIC_CFLAGS) -lcrypto -L. -lcsv $(SHARED_CFLAGS) -ldl -lpthread

ioctl_get_key: ioctl_get_key.c
	gcc -Wall $(CFLAGS) -o ioctl_get_key ioctl_get_key.c -L. libcsv.a $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS) -ldl -lpthread

calc-vm-digest: calc_vm_digest.c
	gcc -Wall $(CFLAGS) -o calc-vm-digest calc_vm_digest.c $(STATIC_CFLAGS) -lcrypto $(SHARED_CFLAGS)  -ldl -lpthread

clean:
	rm *attestation calc-vm-digest *key libcsv.*

release_csv_cipher:
	rm -rf $(CSV_CIPHER_DIR)
	mkdir $(CSV_CIPHER_DIR)
	cp csv_status.h demo.c $(CSV_CIPHER_DIR)
	cp release_csv_cipher.Makefile $(CSV_CIPHER_DIR)/Makefile
	cp $(CSV_SDK_DIR)/csv_status.c $(CSV_CIPHER_DIR)
