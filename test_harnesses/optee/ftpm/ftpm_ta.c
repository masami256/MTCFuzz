// Check fTPM TA presence via TEEC (BUSY is OK: kernel owns the TA).
#include "common.h"
#include <stdio.h>
#include <tee_client_api.h>

// fTPM TA UUID (same as optee_test)
#define TA_FTPM_UUID { 0xBC50D971, 0xD4C9, 0x42C4, \
    {0x82, 0xCB, 0x34, 0x3F, 0xB7, 0xF3, 0x78, 0x96} }
    
int check_ftpm_ta(void)
{
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_UUID uuid = TA_FTPM_UUID;
    TEEC_Result ret;
    uint32_t ret_orig = 0;

    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        EPRINTF("[*]TEEC_InitializeContext() failed: 0x%x\n", ret);
        return -1;
    }

    ret = TEEC_OpenSession(&context, &session, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
    if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
        EPRINTF("[+]skip test, fTPM TA not present\n");
        TEEC_FinalizeContext(&context);
        return -1;
    }

    if (ret != TEEC_ERROR_BUSY && ret == TEEC_SUCCESS) {
        TEEC_CloseSession(&session);
    }
        
    TEEC_FinalizeContext(&context);
    return 0;
}