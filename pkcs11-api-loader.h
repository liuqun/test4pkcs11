/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef PKCS11_API_LOADER_H_
#define PKCS11_API_LOADER_H_

#include "config.h"
#ifndef HAVE_OPENCRYPTOKI_PKCS11_H
#error // 找不到 opencryptoki/pkcs11.h
#endif

#include <opencryptoki/pkcs11.h>

/**
 * A structure to hold all successfully loaded PKCS#11 API functions
 *
 * @details
 * PKCS#11 API functions are loaded from any DLL(dynamically loaded library) file.
 *
 * Usage:
 * ```
 * pkcs11_api_t *api;
 * api = new_pkcs11_api_instance("libxxx.so");
 * api->functions->C_Initialize(NULL);
 * api->functions->C_Finalize(NULL);
 * delete_pkcs11_api_instance(api);
 * ```
 */
typedef struct pkcs11_api_t {
    /**
     * PKCS#11 API function list
     */
    CK_FUNCTION_LIST_PTR functions;
} pkcs11_api_t;


/**
 * Create a pkcs11_api_t instance.
 *
 * @param file -- pkcs11 library file to dlopen()
 * @return -- library abstraction
 */
pkcs11_api_t *new_pkcs11_api_instance(const char *file);

/**
 * Delete all resources of a pkcs11_api_t instance.
 */
void delete_pkcs11_api_instance(pkcs11_api_t *instance);

#endif /* PKCS11_API_LOADER_H_ */
