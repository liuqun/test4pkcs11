/* encoding:utf8 */

/*
 * 源代码取自 IBM 开源项目 openCryptoki, 引用链接为:
 * https://github.com/opencryptoki/opencryptoki/blob/e460cc1ab72b3b27e648ff883b74bac0733c71af/doc/opencryptoki-howto.md#10-appendix-a-sample-program
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>

#include "config.h"
#ifndef HAVE_OPENCRYPTOKI_PKCS11_H
#error // 找不到 opencryptoki/pkcs11.h
#endif

#include <opencryptoki/pkcs11.h>

#define CFG_SLOT        0x0004
#define CFG_PKCS_INFO   0X0008
#define CFG_TOKEN_INFO  0x0010

CK_RV init(void);
CK_RV cleanup(void);
CK_RV get_slot_list(int, CK_CHAR_PTR);
CK_RV display_slot_info(void);
CK_RV display_token_info(void);

void *dll_ptr;
CK_FUNCTION_LIST_PTR    function_ptr = NULL;
CK_SLOT_ID_PTR          slot_list = NULL;
CK_ULONG                slot_count = 0;
int in_slot;

int main(int argc, char *argv[])
{
    CK_RV rc;                   /* Return Code */
    CK_FLAGS flags = 0;         /* Bit Mask for what options were passed in */
    CK_CHAR_PTR slot = NULL;    /* The PKCS slot number */

    /* Load the PKCS11 library */
    init();

    /* Get the slot list and indicate if a slot number was passed in or not */
    get_slot_list(flags, slot);

    /* Display the current token and slot info */
    display_token_info();
    display_slot_info();

    /* We are done, free the memory we may have allocated */
    free(slot);
    return rc;
}

CK_RV get_slot_list(int cond, CK_CHAR_PTR slot)
{
    CK_RV rc;   /* Return code */

    /* Find out how many tokens are present in the slots */
    rc = function_ptr->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
    if (rc != CKR_OK) {
        printf("Error getting number of slots: 0x%X\n", (int)rc);
        return rc;
    }

    /* Allocate enough space for the slots information */
    slot_list = (CK_SLOT_ID_PTR) malloc(slot_count*sizeof(CK_SLOT_ID));

    rc = function_ptr->C_GetSlotList(TRUE, slot_list, &slot_count);
    if (rc != CKR_OK) {
        printf("Error getting slot list: 0x%X\n", (int)rc);
        return rc;
    }

    return rc;
}

CK_RV display_slot_info(void)
{
    CK_RV           rc;         /* Return Code */
    CK_SLOT_INFO    slot_info;   /* Structure to hold slot information */
    int             lcv;        /* Loop Control Variable */

    for (lcv = 0; lcv < slot_count; lcv++) {
        /* Get the info for the slot we are examining and store in slot_info */
        rc = function_ptr->C_GetSlotInfo(slot_list[lcv], &slot_info);
        if (rc != CKR_OK) {
            printf("Error getting the slot info: 0x%X\n", (int)rc);
            return rc;
        }

        /* Display the slot information */
        printf("Slot #%d Info\n", (int)slot_list[lcv]);
        printf("\tDescription: %.64s\n", slot_info.slotDescription);
        printf("\tManufacturer: %.32s\n", slot_info.manufacturerID);
        printf("\tFlags: 0x%X\n", (int)slot_info.flags);
        printf("\tHardware Version: %d.%d\n", slot_info.hardwareVersion.major,
                                              slot_info.hardwareVersion.minor);
        printf("\tFirmware Version: %d.%d\n", slot_info.firmwareVersion.major,
                                              slot_info.firmwareVersion.minor);
    }
    return CKR_OK;
}

CK_RV display_token_info(void)
{
    CK_RV           rc;         /* Return Code */
    CK_TOKEN_INFO   token_info;  /* Structure to hold token information */
    int             lcv;        /* Loop Control Variable */

    for (lcv = 0; lcv < slot_count; lcv++) {
        /* Get the Token info for each slot in the system */
        rc = function_ptr->C_GetTokenInfo(slot_list[lcv], &token_info);
        if (rc != CKR_OK) {
            printf("Error getting token info: 0x%X\n", (int)rc);
            return rc;
        }

        /* Display the token information */
        printf("Token #%d Info:\n", (int)slot_list[lcv]);
        printf("\tLabel: %.32s\n", token_info.label);
        printf("\tManufacturer: %.32s\n", token_info.manufacturerID);
        printf("\tModel: %.16s\n", token_info.model);
        printf("\tSerial Number: %.16s\n", token_info.serialNumber);
        printf("\tFlags: 0x%X\n", (int)token_info.flags);
        printf("\tSessions: %d/%d\n", (int)token_info.ulSessionCount,
                                      (int)token_info.ulMaxSessionCount);
        printf("\tR/W Sessions: %d/%d\n", (int)token_info.ulRwSessionCount,
                                          (int)token_info.ulMaxRwSessionCount);
        printf("\tPIN Length: %d-%d\n", (int)token_info.ulMinPinLen,
                                        (int)token_info.ulMaxPinLen);
        printf("\tPublic Memory: 0x%X/0x%X\n", (int)token_info.ulFreePublicMemory,
                                               (int)token_info.ulTotalPublicMemory);
        printf("\tPrivate Memory: 0x%X/0x%X\n", (int)token_info.ulFreePrivateMemory,
                                               (int)token_info.ulTotalPrivateMemory);
        printf("\tHardware Version: %d.%d\n", (int)token_info.hardwareVersion.major,
                                              (int)token_info.hardwareVersion.minor);
        printf("\tFirmware Version: %d.%d\n", token_info.firmwareVersion.major,
                                              token_info.firmwareVersion.minor);
        printf("\tTime: %.16s\n", token_info.utcTime);
    }
    return CKR_OK;
}

CK_RV init(void)
{
    CK_RV rc;           /* Return Code */
    void (*sym_ptr)();   /* Pointer for the DLL */

    /* Open the PKCS11 API Shared Library, and inform the user if there is an
     * error
     */
    dll_ptr = dlopen("/usr/lib/opencryptoki/libopencryptoki.so", RTLD_NOW);
    if (!dll_ptr) {
        rc = errno;
        printf("Error loading PKCS#11 library: 0x%X\n", (int)rc);
        fflush(stdout);
        return rc;
    }

    /* Get the list of the PKCS11 functions this token supports */
    sym_ptr = (void (*) ())dlsym(dll_ptr, "C_GetFunctionList");
    if (!sym_ptr) {
        rc = errno;
        printf("Error getting function list: 0x%X\n", (int)rc);
        fflush(stdout);
        cleanup();
    }

    sym_ptr(&function_ptr);

    /* If we get here, we know the slot manager is running and we can use PKCS11
     * calls, so we will execute the PKCS11 Initialize command.
     */
    rc = function_ptr->C_Initialize(NULL);
    if (rc != CKR_OK) {
        printf("Error initializing the PKCS11 library: 0x%X\n", (int)rc);
        fflush(stdout);
        cleanup();
    }

    return CKR_OK;
}

CK_RV cleanup(void)
{
    CK_RV rc;   /* Return Code */

    /* To clean up we will free the slot list we create, call the Finalize
     * routine for PKCS11 and close the dynamically linked library
     */
    free(slot_list);
    rc = function_ptr->C_Finalize(NULL);
    if (dll_ptr)
        dlclose(dll_ptr);

    exit(rc);
}
