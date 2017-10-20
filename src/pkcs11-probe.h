/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef PKCS11_PROBE_H_
#define PKCS11_PROBE_H_

#include "config.h"
#include "pkcs11.h"

typedef struct api_instance_t *api_t;

typedef union {
    void *ptr;
    struct api_instance_t *api;
    struct pkcs11_instance_t *pkcs11;
} pkcs11_t;

typedef enum {
    PROBE_SUCCESS=0,
    PROBE_GENERIC_FAILURE,
} probe_result_t;

#ifdef __cplusplus
extern "C" {
#endif

api_t new_api_instance();
void delete_api_instance(api_t instance);

pkcs11_t new_pkcs11_instance();
void delete_pkcs11_instance(pkcs11_t instance);
const char *pkcs11_which_lib(pkcs11_t instance);
const CK_FUNCTION_LIST_PTR pkcs11_get_api_function_list(pkcs11_t instance);

probe_result_t api_probe(api_t instance, const char *lib);
probe_result_t pkcs11_probe(pkcs11_t instance, const char *lib);

#ifdef __cplusplus
}; /* end of extern "C" */
#endif
#endif /* PKCS11_PROBE_H_ */
