/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include <opencryptoki/pkcs11.h>
#include "pkcs11-probe.h"

/* K&R 代码风格: 使用 4 个空格, 不使用 Tab */

struct api_instance_t {
    void *handle;
};

probe_result_t api_probe(api_t self, const char *lib)
{
    void *handle;

    assert(self);

    handle = NULL;
    handle = dlopen(lib, RTLD_NOW);
    if (!handle) {
        int rc = errno;
        fprintf(stderr, "Failed to open dll library: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }

    self->handle = handle;
    return (PROBE_SUCCESS);
}

struct pkcs11_instance_t {
    struct api_instance_t api;
    const char *from_which_lib;
    CK_FUNCTION_LIST_PTR functions;
};

probe_result_t pkcs11_probe(pkcs11_t self, const char *lib)
{
    CK_FUNCTION_LIST_PTR functions;
    CK_C_GetFunctionList C_GetFunctionList;

    assert(self.ptr);

    if (lib && '\0' != lib[0]) {
        int rc = api_probe(self.api, lib);
        if (rc != PROBE_SUCCESS) {
            return rc;
        }
    }
    if (!lib || '\0' == lib[0]) {
        /* 如果调用者未指定动态库名称, 则从下列备选项中依次进行尝试 */
        const char *list[] = {"/usr/lib/opencryptoki/libopencryptoki.so", NULL};
        lib = list[0];
        do {
            if (api_probe(self.api, lib) == PROBE_SUCCESS) {
                break;
            }
            ++lib;
        } while(lib);
    }

    /* Get the list of the PKCS11 functions this token supports */
    C_GetFunctionList = (CK_C_GetFunctionList) dlsym(self.api->handle, "C_GetFunctionList");
    if (!C_GetFunctionList) {
        int rc = errno;
        fprintf(stderr, "Error getting function list from DLL: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }
    functions = NULL;
    C_GetFunctionList(&functions);
    /* FIXME: Error cases returned by C_GetFunctionList() should be checked here. */
    self.pkcs11->functions = functions;
    self.pkcs11->from_which_lib = lib;
    return PROBE_SUCCESS;
}

const char *pkcs11_which_lib(pkcs11_t instance)
{
    return (instance.pkcs11->from_which_lib);
}

const CK_FUNCTION_LIST_PTR pkcs11_get_api_function_list(pkcs11_t instance)
{
    return (instance.pkcs11->functions);
}

pkcs11_t new_pkcs11_instance()
{
    struct pkcs11_instance_t *instance;

    instance = malloc(sizeof(struct pkcs11_instance_t));
    assert(instance);
	return ((pkcs11_t) instance);
}

void delete_pkcs11_instance(pkcs11_t instance)
{
    if (!instance.ptr) {
        return;
    }
    if (instance.api->handle) {
        dlclose(instance.api->handle);
        instance.api->handle = NULL;
    }
    free(instance.pkcs11);
}
