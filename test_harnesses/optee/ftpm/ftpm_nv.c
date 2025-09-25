#include "common.h"
#include "ftpm_nv.h"

#include <string.h>

/* Build NV_DefineSpace (PWAP, Owner auth handle, empty authValue, ORDINARY/AUTHREAD|AUTHWRITE). */
int build_cmd_nv_definespace(uint32_t nv_index,
                                    uint16_t data_size,
                                    uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_DefineSpace, buf, buf_sz, &off, &size_off)) {
        return -1;
    }
    
    // Handles: authHandle = TPM_RH_OWNER
    if (Tss2_MU_UINT32_Marshal(TPM2_RH_OWNER, buf, buf_sz, &off)) {
        return -1;
    }

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) {
        return -1;  // placeholder
    }

    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) {
        return -1;
    }

    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) {
            return -1;
        }
    }

    // Parameters:
    //  - TPM2B_AUTH auth = "" (size=0)
    TPM2B_AUTH auth = { .size = 0 };
    if (Tss2_MU_TPM2B_AUTH_Marshal(&auth, buf, buf_sz, &off)) {
        return -1;
    }

    //  - TPM2B_NV_PUBLIC publicInfo
    //    Fill TPMS_NV_PUBLIC then wrap as TPM2B_NV_PUBLIC with correct size
    TPMS_NV_PUBLIC p;
    p.nvIndex = nv_index;
    p.nameAlg = TPM2_ALG_SHA256;

    // attributes: AUTHREAD | AUTHWRITE (and OWNERREAD/OWNERWRITE optional)
    p.attributes = (TPMA_NV)(TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE);
    // You may also allow owner read/write if you want:
    // p.attributes.val |= TPMA_NV_OWNERREAD;
    // p.attributes.val |= TPMA_NV_OWNERWRITE;

    p.authPolicy.size = 0;      // no policy
    p.dataSize = data_size;     // fixed size (we'll write within this bound)

    // Marshal as TPM2B_NV_PUBLIC: write size (of TPMS_NV_PUBLIC), then TPMS_NV_PUBLIC body
    // First, marshal TPMS_NV_PUBLIC into a temp to know its length
    uint8_t tmp_pub[256];
    size_t tmp_off = 0;
    if (Tss2_MU_TPMS_NV_PUBLIC_Marshal(&p, tmp_pub, sizeof(tmp_pub), &tmp_off)) {
        return -1;
    }

    // Now write size and the body
    if (Tss2_MU_UINT16_Marshal((UINT16)tmp_off, buf, buf_sz, &off)) {
        return -1;
    }

    // Copy the marshaled body
    if (off + tmp_off > buf_sz) {
        return -1;
    }

    memcpy(buf + off, tmp_pub, tmp_off);
    off += tmp_off;

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) {
        return -1;
    }
    *out_len = off;
    return 0;
}

/* Build NV_Write with PWAP (authHandle = nvIndex, nvIndex). Writes 'data' at offset 0. */
int build_cmd_nv_write(uint32_t nv_index,
                              const uint8_t *data, uint16_t data_len,
                              uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_Write, buf, buf_sz, &off, &size_off)) {
        return -1;
    }

    // Handles: authHandle (index auth) + nvIndex
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) {
        return -1;  // authHandle = nvIndex (AUTHWRITE)
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) {
        return -1;  // nvIndex
    }

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) {
        return -1;  // placeholder
    }
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) {
        return -1;
    }
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) {
            return -1;
        }
    }

    // Parameters: TPM2B_MAX_NV_BUFFER data, UINT16 offset
    TPM2B_MAX_NV_BUFFER nvdata;
    if (data_len > sizeof(nvdata.buffer)) {
        return -1;
    }
    nvdata.size = data_len;
    memcpy(nvdata.buffer, data, data_len);

    if (Tss2_MU_TPM2B_MAX_NV_BUFFER_Marshal(&nvdata, buf, buf_sz, &off)) {
        return -1;
    }
    if (Tss2_MU_UINT16_Marshal(0 /*offset*/, buf, buf_sz, &off)) {
        return -1;
    }

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) {
        return -1;
    }
    *out_len = off;
    return 0;
}

/* Build NV_Read with PWAP (authHandle = nvIndex, nvIndex). Reads 'size' at offset 0. */
int build_cmd_nv_read(uint32_t nv_index,
                             uint16_t read_size,
                             uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_Read, buf, buf_sz, &off, &size_off)) {
        return -1;
    }

    // Handles: authHandle (index auth) + nvIndex
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) {
        return -1;  // authHandle = nvIndex (AUTHREAD)
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) {
        return -1;  // nvIndex
    }

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) {
        return -1;  // placeholder
    }
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) {
        return -1;
    }
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) {
            return -1;
        }
    }

    // Parameters: UINT16 size, UINT16 offset
    if (Tss2_MU_UINT16_Marshal(read_size, buf, buf_sz, &off)) {
        return -1;
    }
    if (Tss2_MU_UINT16_Marshal(0 /*offset*/, buf, buf_sz, &off)) {
        return -1;
    }

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) {
        return -1;
    }
    *out_len = off;
    return 0;
}

/* Build NV_UndefineSpace (PWAP, Owner auth, target nvIndex). */
int build_cmd_nv_undefinespace(uint32_t nv_index,
                                      uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_UndefineSpace, buf, buf_sz, &off, &size_off)) {
        return -1;
    }

    // Handles: authHandle = TPM_RH_OWNER, nvIndex
    if (Tss2_MU_UINT32_Marshal(TPM2_RH_OWNER, buf, buf_sz, &off)) {
        return -1;
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) {
        return -1;
    }

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) {
        return -1;  // placeholder
    }
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) {
        return -1;
    }
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) {
            return -1;
        }
    }

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) {
        return -1;
    }
    *out_len = off;
    return 0;
}

/* Unmarshal NV_Read response payload and print it as string/hex. */
void dump_nv_read_response(const uint8_t *rsp, size_t rsp_len)
{
    // SESSIONS response layout:
    // [0..9]   : TPM2_RESPONSE_HEADER (10 bytes)
    // [10..13] : parameterSize (UINT32)
    // [14..]   : parameters (here: TPM2B_MAX_NV_BUFFER)
    // [..end]  : responseAuths

    if (rsp_len <= 14) {
        printf("[*]NV_Read: short response\n");
        return;
    }

    // 1) Read parameterSize
    UINT32 param_size = 0;
    size_t off = 0;
    if (Tss2_MU_UINT32_Unmarshal(rsp + 10, rsp_len - 10, &off, &param_size) != TSS2_RC_SUCCESS) {
        printf("[*]NV_Read: failed to read parameterSize\n");
        return;
    }

    // 2) Unmarshal TPM2B_MAX_NV_BUFFER from the parameters area (start at 10+4)
    TPM2B_MAX_NV_BUFFER out = {0};
    size_t off2 = 0; // <-- reset offset for the parameters sub-buffer
    if (Tss2_MU_TPM2B_MAX_NV_BUFFER_Unmarshal(rsp + 14, rsp_len - 14, &off2, &out)
        != TSS2_RC_SUCCESS) {
        printf("[*]NV_Read: unmarshal failed\n");
        return;
    }

    printf("[+]NV_Read data (size=%u): ", out.size);
    for (uint16_t i = 0; i < out.size; i++) printf("%02x ", out.buffer[i]);
    printf("\n");

    printf("[+]NV_Read as string: ");
    for (uint16_t i = 0; i < out.size; i++) {
        unsigned char c = out.buffer[i];
        putchar((c >= 32 && c <= 126) ? c : '.');
    }
    putchar('\n');
}