// ftpm_test_simple.c - fTPM NV Define/Write/Read/Undefine via /dev/tpmrm0 (PWAP, empty auth)
//
// - Uses MU to build TPM2 commands (TPM2_ST_SESSIONS + AuthArea=PWAP)
// - Defines an ORDINARY NV index with AUTHREAD/AUTHWRITE and empty authValue
// - Writes "foobar", reads it back, then undefines the index
// - Reuses send_tpm_cmd_mu() for I/O
//
// Build:
//   gcc -Wall ftpm_test_simple.c -o ftpm_test_simple -lteec -ltss2-mu -ltss2-sys
// Run:
//   ./ftpm_test_simple

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <tee_client_api.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#define DEV_TPMRM0 "/dev/tpmrm0"

// fTPM TA UUID (same as optee_test)
#define TA_FTPM_UUID { 0xBC50D971, 0xD4C9, 0x42C4, \
    {0x82, 0xCB, 0x34, 0x3F, 0xB7, 0xF3, 0x78, 0x96} }

// Choose an NV index in the NV handle range (0x01000000 - 0x01FFFFFF)
#define NV_INDEX   0x0100F00Du

// Normalize a TPM RC to its 16-bit base (strip format/layer bits)
static inline uint32_t rc_base(uint32_t rc) { return rc & 0xFFFFu; }

/* Check fTPM TA presence via TEEC (BUSY is OK: kernel owns the TA). */
static int check_ftpm_ta(void)
{
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_UUID uuid = TA_FTPM_UUID;
    TEEC_Result ret;
    uint32_t ret_orig = 0;

    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        printf("[*]TEEC_InitializeContext() failed: 0x%x\n", ret);
        return -1;
    }
    ret = TEEC_OpenSession(&context, &session, &uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
    if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
        printf("[+]skip test, fTPM TA not present\n");
        TEEC_FinalizeContext(&context);
        return -1;
    }
    if (ret != TEEC_ERROR_BUSY && ret == TEEC_SUCCESS)
        TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
    return 0;
}

/* Send a raw TPM command, unmarshal the 10-byte response header with MU,
 * read the remaining bytes, and optionally return the TPM RC.
 * Returns 0 if TPM_RC_SUCCESS, otherwise -1 (caller can inspect tpm_rc_out).
 */
static int send_tpm_cmd_mu(int fd,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           TPM2_RC *tpm_rc_out)
{
    // Transmit command
    ssize_t w = write(fd, in, in_len);
    if (w != (ssize_t)in_len) return -1;

    // Read fixed-size response header (10 bytes)
    uint8_t hdr_buf[10];
    ssize_t r = read(fd, hdr_buf, sizeof(hdr_buf));
    if (r != (ssize_t)sizeof(hdr_buf)) return -1;

    // Unmarshal: tag (TPM2_ST), paramSize (UINT32), responseCode (UINT32)
    size_t off = 0;
    TPM2_ST tag = 0;
    UINT32 paramSize = 0;
    TPM2_RC rc = 0;

    if (Tss2_MU_TPM2_ST_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &tag)) return -1;
    if (Tss2_MU_UINT32_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &paramSize)) return -1;
    if (Tss2_MU_UINT32_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &rc)) return -1;

    if (tpm_rc_out) *tpm_rc_out = rc;

    if (paramSize < sizeof(hdr_buf) || paramSize > *out_len) return -1;

    memcpy(out, hdr_buf, sizeof(hdr_buf));
    size_t remaining = paramSize - sizeof(hdr_buf);
    if (remaining) {
        ssize_t r2 = read(fd, out + sizeof(hdr_buf), remaining);
        if (r2 != (ssize_t)remaining) return -1;
    }
    *out_len = paramSize;

    return (rc == TPM2_RC_SUCCESS) ? 0 : -1;
}

/* Marshal one PWAP AuthArea (TPM_RS_PW, empty hmac) and return its byte size. */
static int marshal_pwap_auth(uint8_t *buf, size_t buf_sz, size_t *autharea_len)
{
    // TPMS_AUTH_COMMAND: sessionHandle, nonce(size=0), sessionAttributes(1B), hmac(size=0)
    TPMS_AUTH_COMMAND a;
    a.sessionHandle = TPM2_RS_PW;      // password session
    a.nonce.size = 0;                   // no nonce
    a.sessionAttributes = 0;            // no attributes
    a.hmac.size = 0;                    // empty password

    size_t off = 0;
    TSS2_RC rc = Tss2_MU_TPMS_AUTH_COMMAND_Marshal(&a, buf, buf_sz, &off);
    if (rc != TSS2_RC_SUCCESS) return -1;
    *autharea_len = off;
    return 0;
}

/* Begin a "SESSIONS" command header: tag, size placeholder, commandCode. */
static int begin_cmd_sessions(UINT32 cc, uint8_t *buf, size_t buf_sz,
                              size_t *off_io, size_t *size_off_out)
{
    size_t off = *off_io;
    if (Tss2_MU_TPM2_ST_Marshal(TPM2_ST_SESSIONS, buf, buf_sz, &off)) return -1;
    UINT32 size_placeholder = 0;
    size_t size_off = off;
    if (Tss2_MU_UINT32_Marshal(size_placeholder, buf, buf_sz, &off)) return -1;
    if (Tss2_MU_UINT32_Marshal(cc, buf, buf_sz, &off)) return -1;
    *off_io = off;
    *size_off_out = size_off;
    return 0;
}

/* Backfill the total command size at 'size_off'. */
static int finalize_cmd_size(uint8_t *buf, size_t buf_sz, size_t size_off, size_t total_off)
{
    UINT32 total = (UINT32)total_off;
    size_t tmp = size_off;
    return (Tss2_MU_UINT32_Marshal(total, buf, buf_sz, &tmp) == TSS2_RC_SUCCESS) ? 0 : -1;
}

/* Build NV_DefineSpace (PWAP, Owner auth handle, empty authValue, ORDINARY/AUTHREAD|AUTHWRITE). */
static int build_cmd_nv_definespace(uint32_t nv_index,
                                    uint16_t data_size,
                                    uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_DefineSpace, buf, buf_sz, &off, &size_off)) return -1;

    // Handles: authHandle = TPM_RH_OWNER
    if (Tss2_MU_UINT32_Marshal(TPM2_RH_OWNER, buf, buf_sz, &off)) return -1;

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) return -1;  // placeholder
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) return -1;
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) return -1;
    }

    // Parameters:
    //  - TPM2B_AUTH auth = "" (size=0)
    TPM2B_AUTH auth = { .size = 0 };
    if (Tss2_MU_TPM2B_AUTH_Marshal(&auth, buf, buf_sz, &off)) return -1;

    //  - TPM2B_NV_PUBLIC publicInfo
    //    Fill TPMS_NV_PUBLIC then wrap as TPM2B_NV_PUBLIC with correct size
    TPMS_NV_PUBLIC p;
    p.nvIndex = nv_index;
    p.nameAlg = TPM2_ALG_SHA256;

    // attributes: AUTHREAD | AUTHWRITE (and OWNERREAD/OWNERWRITE optional)
    // Using .val to avoid bitfield portability issues
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
    if (Tss2_MU_TPMS_NV_PUBLIC_Marshal(&p, tmp_pub, sizeof(tmp_pub), &tmp_off))
        return -1;

    // Now write size and the body
    if (Tss2_MU_UINT16_Marshal((UINT16)tmp_off, buf, buf_sz, &off)) return -1;
    // Copy the marshaled body
    if (off + tmp_off > buf_sz) return -1;
    memcpy(buf + off, tmp_pub, tmp_off);
    off += tmp_off;

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) return -1;
    *out_len = off;
    return 0;
}

/* Build NV_Write with PWAP (authHandle = nvIndex, nvIndex). Writes 'data' at offset 0. */
static int build_cmd_nv_write(uint32_t nv_index,
                              const uint8_t *data, uint16_t data_len,
                              uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_Write, buf, buf_sz, &off, &size_off)) return -1;

    // Handles: authHandle (index auth) + nvIndex
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) return -1;  // authHandle = nvIndex (AUTHWRITE)
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) return -1;  // nvIndex

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) return -1;  // placeholder
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) return -1;
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) return -1;
    }

    // Parameters: TPM2B_MAX_NV_BUFFER data, UINT16 offset
    TPM2B_MAX_NV_BUFFER nvdata;
    if (data_len > sizeof(nvdata.buffer)) return -1;
    nvdata.size = data_len;
    memcpy(nvdata.buffer, data, data_len);

    if (Tss2_MU_TPM2B_MAX_NV_BUFFER_Marshal(&nvdata, buf, buf_sz, &off)) return -1;
    if (Tss2_MU_UINT16_Marshal(0 /*offset*/, buf, buf_sz, &off)) return -1;

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) return -1;
    *out_len = off;
    return 0;
}

/* Build NV_Read with PWAP (authHandle = nvIndex, nvIndex). Reads 'size' at offset 0. */
static int build_cmd_nv_read(uint32_t nv_index,
                             uint16_t read_size,
                             uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_Read, buf, buf_sz, &off, &size_off)) return -1;

    // Handles: authHandle (index auth) + nvIndex
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) return -1;  // authHandle = nvIndex (AUTHREAD)
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) return -1;  // nvIndex

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) return -1;  // placeholder
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) return -1;
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) return -1;
    }

    // Parameters: UINT16 size, UINT16 offset
    if (Tss2_MU_UINT16_Marshal(read_size, buf, buf_sz, &off)) return -1;
    if (Tss2_MU_UINT16_Marshal(0 /*offset*/, buf, buf_sz, &off)) return -1;

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) return -1;
    *out_len = off;
    return 0;
}

/* Build NV_UndefineSpace (PWAP, Owner auth, target nvIndex). */
static int build_cmd_nv_undefinespace(uint32_t nv_index,
                                      uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    size_t off = 0, size_off = 0;
    if (begin_cmd_sessions(TPM2_CC_NV_UndefineSpace, buf, buf_sz, &off, &size_off)) return -1;

    // Handles: authHandle = TPM_RH_OWNER, nvIndex
    if (Tss2_MU_UINT32_Marshal(TPM2_RH_OWNER, buf, buf_sz, &off)) return -1;
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off)) return -1;

    // authorizationSize + AuthArea(PWAP)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off)) return -1;  // placeholder
    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len)) return -1;
    off += auth_len;
    // backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp)) return -1;
    }

    if (finalize_cmd_size(buf, buf_sz, size_off, off)) return -1;
    *out_len = off;
    return 0;
}

/* Unmarshal NV_Read response payload and print it as string/hex. */
static void dump_nv_read_response(const uint8_t *rsp, size_t rsp_len)
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


int main(void)
{
    printf("[+]Test start\n");
    if (check_ftpm_ta())
        return -1;
    printf("[+]TA check ok\n");

    int fd = open(DEV_TPMRM0, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("[*]Failed to open %s: %s\n", DEV_TPMRM0, strerror(errno));
        return -1;
    }

    // Small settle delay helps some fTPM builds right after boot
    usleep(500 * 1000); // 500ms

    // 1) Define NV index (size=6, for "foobar"), ORDINARY with AUTHREAD/AUTHWRITE, empty auth
    {
        uint8_t cmd[512], rsp[256];
        size_t cmd_len = 0, rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_definespace(NV_INDEX, 6, cmd, sizeof(cmd), &cmd_len)) {
            printf("[*]Failed to build NV_DefineSpace\n");
            close(fd); return -1;
        }
        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_DefineSpace failed (rc=0x%08x)\n", last_rc);
            close(fd); return -1;
        }
        printf("[+]NV_DefineSpace OK (rsp_len=0x%zx)\n", rsp_len);
    }

    // 2) NV_Write "foobar"
    {
        const uint8_t payload[] = { 'f','o','o','b','a','r' };
        uint8_t cmd[512], rsp[256];
        size_t cmd_len = 0, rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_write(NV_INDEX, payload, (uint16_t)sizeof(payload),
                               cmd, sizeof(cmd), &cmd_len)) {
            printf("[*]Failed to build NV_Write\n");
            goto undefine;
        }
        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            // Retry on TESTING just in case (rare here)
            int delay_ms = 100, attempts = 10, ok = 0;
            for (int i = 0; i < attempts && rc_base(last_rc) == 0x01DAu; i++) {
                usleep(delay_ms * 1000);
                if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc) == 0) { ok = 1; break; }
                if (delay_ms < 1000) delay_ms <<= 1;
            }
            if (!ok) {
                printf("[*]NV_Write failed (rc=0x%08x)\n", last_rc);
                goto undefine;
            }
        }
        printf("[+]NV_Write OK (wrote \"%s\")\n", "foobar");
    }

    // 3) NV_Read 6 bytes
    {
        uint8_t cmd[512], rsp[256];
        size_t cmd_len = 0, rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_read(NV_INDEX, 6, cmd, sizeof(cmd), &cmd_len)) {
            printf("[*]Failed to build NV_Read\n");
            goto undefine;
        }
        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_Read failed (rc=0x%08x)\n", last_rc);
            goto undefine;
        }
        printf("[+]NV_Read OK (rsp_len=0x%zx)\n", rsp_len);

        dump_nv_read_response(rsp, rsp_len);
    }

undefine:
    // 4) Undefine NV index (owner auth)
    {
        uint8_t cmd[512], rsp[256];
        size_t cmd_len = 0, rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_undefinespace(NV_INDEX, cmd, sizeof(cmd), &cmd_len)) {
            printf("[*]Failed to build NV_UndefineSpace\n");
        } else if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_UndefineSpace failed (rc=0x%08x)\n", last_rc);
        } else {
            printf("[+]NV_UndefineSpace OK\n");
        }
    }

    close(fd);
    printf("[+]Done\n");
    return 0;
}
