/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef PKCS11_PROBE_H_
#define PKCS11_PROBE_H_

#include "config.h"
#ifndef HAVE_OPENCRYPTOKI_PKCS11_H
#error // 找不到 opencryptoki/pkcs11.h
#endif
#include <opencryptoki/pkcs11.h>

typedef struct api_instance_t *api_t;

api_t new_api_instance();
void delete_api_instance(api_t instance);

typedef union {
    void *ptr;
    struct api_instance_t *api;
    struct pkcs11_instance_t *pkcs11;
} pkcs11_t;

pkcs11_t new_pkcs11_instance();
void delete_pkcs11_instance(pkcs11_t instance);
const char *pkcs11_which_lib(pkcs11_t instance);
const CK_FUNCTION_LIST_PTR pkcs11_get_api_function_list(pkcs11_t instance);

typedef enum {
    PROBE_SUCCESS=0,
    PROBE_GENERIC_FAILURE,
} probe_result_t;

probe_result_t api_probe(api_t instance, const char *lib);
probe_result_t pkcs11_probe(pkcs11_t instance, const char *lib);

#endif /* PKCS11_PROBE_H_ */
