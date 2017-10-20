#include "config.h"

#ifdef HAVE_P11_KIT
#include <p11-kit/pkcs11.h>
#else
    #ifdef HAVE_OPENCRYPTOKI_PKCS11_H
    #include <opencryptoki/pkcs11.h>
    #else
    #error // You should install either opencryptoki or p11-kit development files!
    #endif
#endif

#undef CKM_SHA256_RSA_PKCS
#define CKM_SHA256_RSA_PKCS (0x40) // NOTE: opencryptoki<=v2.4.2 gives us a wrong constant value

#undef CKM_SHA256_RSA_PKCS_PSS
#define CKM_SHA256_RSA_PKCS_PSS (0x43) // NOTE: opencryptoki<=v3.2 does not support SHA256 RSA signature using PSS padding sheme
