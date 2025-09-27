#include "common.h"
#include "ftpm_nv.h"

#include <string.h>
#include <unistd.h>

static int hexstr_to_bytes(const char *s, uint8_t **out, uint16_t *out_len) {
    size_t len = strlen(s);
    if (len % 2 != 0) {
        return -1;
    }

    size_t n = len / 2;
    if (n > 0xFFFF) {
        n = 0xFFFF; // fits into uint16_t
    }

    uint8_t *buf = (uint8_t *)malloc(n);
    if (!buf) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        char tmp[3] = { s[i * 2], s[i * 2 + 1], 0 };
        buf[i] = (uint8_t) strtoul(tmp, NULL, 16);
    }
    *out = buf;
    *out_len = (uint16_t)n;
    return 0;
}

static int nvwrite_load_fuzz_text_file(const char *path, nvwrite_fuzz_input_t *out)
{
    memset(out, 0, sizeof(*out));
    out->payload = NULL;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    char line[4096];
    char *lines[8] = {0};
    int ok = -1; /* assume failure */

    /* Read 8 lines from the text file */
    for (int i = 0; i < 8; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            goto cleanup;
        }
        line[strcspn(line, "\r\n")] = 0; /* trim newline */
        lines[i] = strdup(line);
        if (!lines[i]) {
            goto cleanup;
        }
    }

    fclose(fp);
    fp = NULL;

    /* Parse numeric values from text lines */
    out->flags0              = (uint8_t)  strtoul(lines[0], NULL, 16);
    out->flags1              = (uint8_t)  strtoul(lines[1], NULL, 16);
    out->declared_size_delta = (int16_t) strtol (lines[2], NULL, 16);
    out->offset_delta        = (int16_t) strtol (lines[3], NULL, 16);
    out->authsize_delta      = (int16_t) strtol (lines[4], NULL, 16);
    out->swap_handles        = (uint32_t) strtoul(lines[5], NULL, 16);
    out->payload_len         = (uint16_t) strtoul(lines[6], NULL, 16); /* declared length */

    uint16_t actual_len = 0;
    if (hexstr_to_bytes(lines[7], &out->payload, &actual_len)) {
        goto cleanup;
    }

    /* Do not fail if declared length and actual length mismatch */
    if (actual_len != out->payload_len) {
        printf("[*] Warning: declared_len=%u, actual_len=%u (mismatch allowed)\n",
               out->payload_len, actual_len);
    }

    ok = 0;

cleanup:
    /* Free all temporary line buffers */
    for (int i = 0; i < 8; i++) {
        if (lines[i]) {
            free(lines[i]);
        }
    }

    if (fp) {
        fclose(fp);
    }

    if (ok != 0) {
        free(out->payload);
        out->payload = NULL;
    }

    return ok;
}

// Build NV_DefineSpace (PWAP, Owner auth handle, empty authValue, ORDINARY/AUTHREAD|AUTHWRITE).
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

// Build NV_Write with PWAP (authHandle = nvIndex, nvIndex). Writes 'data' at offset 0.
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

// Build NV_Read with PWAP (authHandle = nvIndex, nvIndex). Reads 'size' at offset 0.
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

// Build NV_UndefineSpace (PWAP, Owner auth, target nvIndex).
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

// Unmarshal NV_Read response payload and print it as string/hex.
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

int nv_write_start_fuzz_test(options_t *fuzz_opt)
{
    int rc = 0;
    int fd = fuzz_opt->fd;
    nvwrite_fuzz_input_t input = { };

    if (nvwrite_load_fuzz_text_file(fuzz_opt->infile, &input)) {
        printf("[*]Failxed to parse input text %s\n", fuzz_opt->infile);
        return -1;
    }

    printf("[+]Loading input text %s succeeded\n", fuzz_opt->infile);
    
    // Small settle delay helps some fTPM builds right after boot
    usleep(500 * 1000); // 500ms

    // 1) Define NV index (size=6, for "foobar"), ORDINARY with AUTHREAD/AUTHWRITE, empty auth
    {
        uint8_t cmd[512], rsp[256];
        size_t cmd_len = 0, rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_definespace(NV_INDEX, 6, cmd, sizeof(cmd), &cmd_len)) {
            printf("[*]Failed to build NV_DefineSpace\n");
            return -1;
        }

        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_DefineSpace failed (rc=0x%08x)\n", last_rc);
            return -1;
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
            rc = -1;
            goto undefine;
        }
        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            // Retry on TESTING just in case (rare here)
            int delay_ms = 100, attempts = 10, ok = 0;
            for (int i = 0; i < attempts && rc_base(last_rc) == 0x01DAu; i++) {
                usleep(delay_ms * 1000);
                if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc) == 0) { ok = 1; break; }
                if (delay_ms < 1000) {
                    delay_ms <<= 1;
                }
            }
            if (!ok) {
                printf("[*]NV_Write failed (rc=0x%08x)\n", last_rc);
                rc = -1;
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
            rc = -1;
            goto undefine;
        }
        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_Read failed (rc=0x%08x)\n", last_rc);
            rc = -1;
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
            rc = -1;
        } else if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_UndefineSpace failed (rc=0x%08x)\n", last_rc);
            rc = -1;
        } else {
            printf("[+]NV_UndefineSpace OK\n");
        }
    }
    return rc;
}

