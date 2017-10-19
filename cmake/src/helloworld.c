/* (Using UTF-8 encoding for Chinese characters) */

#include <stdio.h>
#include "pkcs11-probe.h"

void foobar()
{
    int rc;
    pkcs11_t instance;
    const char *lib = "/usr/lib/opencryptoki/libopencryptoki.so";

    instance = new_pkcs11_instance();
    rc = pkcs11_probe(instance, lib);
    if (rc != PROBE_SUCCESS) {
        fprintf(stderr, "Error: Cannot load %s\n", lib);
    } else {
        printf("Successfully loaded %s\n", lib);
    }

    delete_pkcs11_instance(instance);
}

int main()
{
	printf("hello\n");
	foobar();
	return (0);
}
