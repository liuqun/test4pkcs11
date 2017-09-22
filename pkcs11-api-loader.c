/* encoding:utf8 */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>

#include "config.h"
#ifndef HAVE_OPENCRYPTOKI_PKCS11_H
#error // 找不到 opencryptoki/pkcs11.h
#endif

#include <opencryptoki/pkcs11.h>
#include "pkcs11-api-loader.h"

///////////////////////////////////////////////////////////////////////////////

/**
 * Private data of an pkcs11_api_t object.
 */
typedef struct private_pkcs11_api_t {
    /**
     * Public PKCS#11 API.
     */
    pkcs11_api_t api;

    /**
     * The void * handle returned from dlopen()
     */
    void *handle;
} private_pkcs11_api_t;

///////////////////////////////////////////////////////////////////////////////

// function new_pkcs11_api_instance(): see header file for usage description
pkcs11_api_t *new_pkcs11_api_instance(const char *file)
{
    private_pkcs11_api_t *self;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_FUNCTION_LIST_PTR functions;
    void *handle;

    /* Open the PKCS11 API Shared Library, and inform the user if there is an error */
    handle = dlopen(file, RTLD_NOW);
    if (!handle) {
        int rc = errno;
        fprintf(stderr, "Failed to open PKCS#11 library file %s: %s: rc=0x%X\n", file, dlerror(), rc);
        return NULL;
    }

    /* Get the list of the PKCS11 functions this token supports */
    C_GetFunctionList = (CK_C_GetFunctionList) dlsym(handle, "C_GetFunctionList");
    if (!C_GetFunctionList) {
        int rc = errno;
        fprintf(stderr, "Error getting function list from %s: %s: rc=0x%X\n", file, dlerror(), rc);
        return NULL;
    }
    functions = NULL;
    C_GetFunctionList(&functions);

    self = malloc(sizeof(*self));
    self->api.functions = functions;
    self->handle = handle;
	return &(self->api);
}

///////////////////////////////////////////////////////////////////////////////

// function delete_pkcs11_api_instance(): see header file for description
void delete_pkcs11_api_instance(pkcs11_api_t *instance)
{
    private_pkcs11_api_t *self;

    if (!instance) {
        return;
    }
    self = (private_pkcs11_api_t *) instance;
    dlclose(self->handle);
}
