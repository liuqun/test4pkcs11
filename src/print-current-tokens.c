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
#include "pkcs11-probe.h"

#define CFG_SLOT        0x0004
#define CFG_PKCS_INFO   0X0008
#define CFG_TOKEN_INFO  0x0010

CK_RV print_slot_info(CK_SLOT_INFO slot_info);
CK_RV print_token_info(CK_TOKEN_INFO token_info);

int main(int argc, char *argv[])
{
    CK_RV rc;
    CK_FUNCTION_LIST_PTR function_ptr = NULL;
    pkcs11_t api;

    api = new_pkcs11_instance();
    if (pkcs11_probe(api, "/usr/lib/opencryptoki/libopencryptoki.so") != PROBE_SUCCESS) {
        fprintf(stderr, "Error initializing the PKCS11 library\n");
        exit(0xFF);
    }
    function_ptr = pkcs11_get_api_function_list(api);

    /* PKCS#11 library initialize */
    rc = function_ptr->C_Initialize(NULL);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error initializing the PKCS#11 library: rc=%X\n", (int)rc);
        goto CLOSE_DLL_BEFORE_EXIT;
    }
    do {
        CK_ULONG slot_count = 0;

        /* Find out how many tokens are present in the slots */
        rc = function_ptr->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
        if (rc != CKR_OK) {
            printf("Error getting number of slots: 0x%X\n", (int)rc);
            break;
        }
        if (slot_count > 0) {
            int i;
            CK_SLOT_ID_PTR slot_list = NULL;

            slot_list = (CK_SLOT_ID_PTR) malloc(slot_count * sizeof(CK_SLOT_ID));
            rc = function_ptr->C_GetSlotList(TRUE, slot_list, &slot_count);

            /* Display token info and slot info for each slot ID in "slot_list" */
            for (i = 0; i < slot_count; i++) {
                CK_RV token_info_err;
                CK_RV slot_info_err;
                CK_TOKEN_INFO token_info; ///< Structure to hold token information
                CK_SLOT_INFO slot_info; ///< Structure to hold slot information
                CK_SLOT_ID id;

                id = slot_list[i];
                token_info_err = function_ptr->C_GetTokenInfo(id, &token_info);
                slot_info_err = function_ptr->C_GetSlotInfo(id, &slot_info);
                if (token_info_err) {
                    printf("Error getting token info: 0x%X\n", (int)token_info_err);
                }
                if (slot_info_err) {
                    printf("Error getting the slot info: 0x%X\n", (int)slot_info_err);
                }
                if (token_info_err || slot_info_err) {
                    continue;
                }
                printf("Token #%d Info:\n", (int)id);
                print_token_info(token_info);
                printf("Slot #%d Info\n", (int)id);
                print_slot_info(slot_info);
            }

            free(slot_list);
            slot_list = NULL;
        }
    } while (0);

    /* PKCS#11 library finalize */
    rc = function_ptr->C_Finalize(NULL);
    if (rc != CKR_OK) {
        fprintf(stderr, "Error finalizing the PKCS#11 library: rc=%X\n", (int)rc);
        goto CLOSE_DLL_BEFORE_EXIT;
    }

    /* Close DLL instance before exit */
CLOSE_DLL_BEFORE_EXIT:
    delete_pkcs11_instance(api);
    return 0;
}

CK_RV print_slot_info(CK_SLOT_INFO slot_info)
{
    /* Display the slot information */
    printf("\tDescription: %.64s\n", slot_info.slotDescription);
    printf("\tManufacturer: %.32s\n", slot_info.manufacturerID);
    printf("\tFlags: 0x%X\n", (int)slot_info.flags);
    printf("\tHardware Version: %d.%d\n", slot_info.hardwareVersion.major,
                                          slot_info.hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", slot_info.firmwareVersion.major,
                                          slot_info.firmwareVersion.minor);
    return CKR_OK;
}

CK_RV print_token_info(CK_TOKEN_INFO token_info)
{
    /* Display the token information */
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
    return CKR_OK;
}
