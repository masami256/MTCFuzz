#include "common.h"
#include "ftpm_nv.h"

#include <string.h>
#include <unistd.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_sys.h>

#define NV_INDEX_START_OFFSET 0x01010000
static int find_free_nv_index(TSS2_SYS_CONTEXT *sys, uint32_t *out_idx) {
    TPMS_CAPABILITY_DATA cap = {0};
    TPMI_YES_NO more = 0;
    uint32_t prop = TPM2_HR_NV_INDEX; // 0x01000000
    uint32_t candidate = NV_INDEX_START_OFFSET;

    do {
        TSS2_RC rc = Tss2_Sys_GetCapability(sys, 0,
                                            TPM2_CAP_HANDLES,
                                            prop, 32,
                                            &more, &cap, 0);
        if (rc != TSS2_RC_SUCCESS) {
            return -1;
        }
        for (UINT32 i = 0; i < cap.data.handles.count; i++) {
            if (cap.data.handles.handle[i] >= candidate) {
                candidate = cap.data.handles.handle[i] + 1;
            }
        }
        prop = candidate;
    } while (more && candidate <= 0x01FFFFFF);

    if (candidate > 0x01FFFFFF) {
        return -1; // no space found
    }

    *out_idx = candidate;

    IPRINTF("Foudn NV index 0x%x\n", *out_idx);
    return 0;
}

// Return a ready-to-use Sys API context, or NULL on failure.
// The caller is responsible for calling Tss2_Sys_Finalize() and Tss2_TctiLdr_Finalize().
TSS2_SYS_CONTEXT *init_sys_context(TSS2_TCTI_CONTEXT **out_tcti)
{
    if (out_tcti == NULL) {
        return NULL;
    }

    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

    // Initialize TCTI with device:/dev/tpmrm0 (or fall back to /dev/tpm0)
    TSS2_RC rc = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti_ctx);
    if (rc != TSS2_RC_SUCCESS || tcti_ctx == NULL) {
        EPRINTF("TctiLdr_Initialize failed: 0x%x\n", rc);
        return NULL;
    }

    size_t sys_ctx_size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sys_ctx = (TSS2_SYS_CONTEXT *)calloc(1, sys_ctx_size);
    if (!sys_ctx) {
        EPRINTF("calloc for sys_ctx failed\n");
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return NULL;
    }

    rc = Tss2_Sys_Initialize(sys_ctx, sys_ctx_size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        EPRINTF("Tss2_Sys_Initialize failed: 0x%x\n", rc);
        free(sys_ctx);
        Tss2_TctiLdr_Finalize(&tcti_ctx);
        return NULL;
    }

    *out_tcti = tcti_ctx;
    return sys_ctx;
}

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
    int ok = -1; // assume failure

    // Read 8 lines from the text file
    for (int i = 0; i < 8; i++) {
        if (!fgets(line, sizeof(line), fp)) {
            goto cleanup;
        }
        line[strcspn(line, "\r\n")] = 0; // trim newline
        lines[i] = strdup(line);
        if (!lines[i]) {
            goto cleanup;
        }
    }

    fclose(fp);
    fp = NULL;

    // Parse numeric values from text lines
    out->flags0              = (uint8_t)  strtoul(lines[0], NULL, 16);
    out->flags1              = (uint8_t)  strtoul(lines[1], NULL, 16);
    out->declared_size_delta = (int16_t) strtol (lines[2], NULL, 16);
    out->offset_delta        = (int16_t) strtol (lines[3], NULL, 16);
    out->authsize_delta      = (int16_t) strtol (lines[4], NULL, 16);
    out->swap_handles        = (uint32_t) strtoul(lines[5], NULL, 16);
    out->payload_len         = (uint16_t) strtoul(lines[6], NULL, 16); // declared length

    uint16_t actual_len = 0;
    if (hexstr_to_bytes(lines[7], &out->payload, &actual_len)) {
        goto cleanup;
    }

    // Do not fail if declared length and actual length mismatch
    if (actual_len != out->payload_len) {
        EPRINTF("Warning: declared_len=%u, actual_len=%u (mismatch allowed)\n",
               out->payload_len, actual_len);
    }

    ok = 0;

cleanup:
    // Free all temporary line buffers
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

// New prototype (last parameter may be NULL when layout is not needed)
// Build TPM2_NV_Write command with MU and record field offsets for fuzzing.
// - nv_index: NV handle to write
// - data/data_len: ACTUAL payload bytes to marshal into TPM2B_MAX_NV_BUFFER
// - buf/buf_sz: output command buffer
// - out_len: resulting total command length
// - layout: optional (can be NULL). When provided, offsets are filled for later mutation.
//
// Note:
// - All multi-byte fields in the raw command are big-endian. MU handles BE for marshaling.
// - We still record offsets so the caller can overwrite fields using be16_write/be32_write.
//
int build_cmd_nv_write(uint32_t nv_index,
                       const uint8_t *data,
                       uint16_t data_len,
                       uint8_t *buf,
                       size_t buf_sz,
                       size_t *out_len,
                       nvwrite_layout_t *layout)
{
    if (out_len == NULL) {
        return -1;
    }
    if (buf == NULL || buf_sz == 0) {
        return -1;
    }
    if (data == NULL && data_len != 0) {
        return -1;
    }

    if (layout != NULL) {
        memset(layout, 0, sizeof(*layout));
        layout->cc = TPM2_CC_NV_Write;
    }

    size_t off = 0;
    size_t size_off = 0;

    // Header (TPM2_ST_SESSIONS) + total size placeholder + commandCode
    if (begin_cmd_sessions(TPM2_CC_NV_Write, buf, buf_sz, &off, &size_off) != 0) {
        return -1;
    }
    if (layout != NULL) {
        layout->hdr_size_off = size_off;
    }

    // Handles: authHandle (nvIndex) + nvIndex
    if (layout != NULL) {
        layout->handles_off = off;
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }

    // authorizationSize (UINT32 placeholder) + AuthArea (PWAP empty auth)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }
    if (layout != NULL) {
        layout->auth_size_off = auth_size_off;
        layout->auth_off = off;
    }

    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len) != 0) {
        return -1;
    }
    off += auth_len;

    // Backfill authorizationSize (big-endian). We use be32_write for clarity.
    be32_write(buf, auth_size_off, (uint32_t)auth_len);

    // Parameters: TPM2B_MAX_NV_BUFFER (data) + UINT16 offset
    if (layout != NULL) {
        layout->params_off = off;
        layout->nvbuf_size_off = off;  // MU will put TPM2B.size here first
    }

    TPM2B_MAX_NV_BUFFER nvdata;
    if (data_len > sizeof(nvdata.buffer)) {
        return -1;
    }
    nvdata.size = data_len;
    if (data_len > 0) {
        memcpy(nvdata.buffer, data, data_len);
    }

    if (Tss2_MU_TPM2B_MAX_NV_BUFFER_Marshal(&nvdata, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }

    if (layout != NULL) {
        layout->nv_offset_off = off;  // next field is the offset (UINT16)
    }
    if (Tss2_MU_UINT16_Marshal(0 /* offset */, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }

    // Finalize total command size in header (big-endian handled inside helper)
    if (finalize_cmd_size(buf, buf_sz, size_off, off) != 0) {
        return -1;
    }

    if (layout != NULL) {
        layout->total_len = off;
    }

    *out_len = off;
    return 0;
}


// Build NV_Read with PWAP (authHandle = nvIndex, nvIndex).
// Reads 'read_size' bytes starting at 'offset'.
int build_cmd_nv_read(uint32_t nv_index,
                      uint16_t read_size,
                      uint16_t offset,
                      uint8_t *buf, size_t buf_sz, size_t *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return -1;
    }

    size_t off = 0;
    size_t size_off = 0;

    // Header (TPM2_ST_SESSIONS) + size placeholder + commandCode
    if (begin_cmd_sessions(TPM2_CC_NV_Read, buf, buf_sz, &off, &size_off) != 0) {
        return -1;
    }

    // Handles: authHandle (nvIndex) + nvIndex
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;  // authHandle = nvIndex (AUTHREAD)
    }
    if (Tss2_MU_UINT32_Marshal(nv_index, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;  // nvIndex
    }

    // authorizationSize (placeholder) + AuthArea (PWAP empty password)
    size_t auth_size_off = off;
    if (Tss2_MU_UINT32_Marshal(0, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }

    size_t auth_len = 0;
    if (marshal_pwap_auth(buf + off, buf_sz - off, &auth_len) != 0) {
        return -1;
    }
    off += auth_len;

    // Backfill authorizationSize
    {
        size_t tmp = auth_size_off;
        if (Tss2_MU_UINT32_Marshal((UINT32)auth_len, buf, buf_sz, &tmp) != TSS2_RC_SUCCESS) {
            return -1;
        }
    }

    // Parameters: UINT16 size, UINT16 offset
    if (Tss2_MU_UINT16_Marshal(read_size, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }
    if (Tss2_MU_UINT16_Marshal(offset, buf, buf_sz, &off) != TSS2_RC_SUCCESS) {
        return -1;
    }

    // Finalize total size
    if (finalize_cmd_size(buf, buf_sz, size_off, off) != 0) {
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
        EPRINTF("NV_Read: short response\n");
        return;
    }

    // 1) Read parameterSize
    UINT32 param_size = 0;
    size_t off = 0;
    if (Tss2_MU_UINT32_Unmarshal(rsp + 10, rsp_len - 10, &off, &param_size) != TSS2_RC_SUCCESS) {
        EPRINTF("NV_Read: failed to read parameterSize\n");
        return;
    }

    // 2) Unmarshal TPM2B_MAX_NV_BUFFER from the parameters area (start at 10+4)
    TPM2B_MAX_NV_BUFFER out = {0};
    size_t off2 = 0; // <-- reset offset for the parameters sub-buffer
    if (Tss2_MU_TPM2B_MAX_NV_BUFFER_Unmarshal(rsp + 14, rsp_len - 14, &off2, &out)
        != TSS2_RC_SUCCESS) {
        EPRINTF("NV_Read: unmarshal failed\n");
        return;
    }

    DPRINTF("NV_Read data (size=%u): ", out.size);
    if (verbose) {
        for (uint16_t i = 0; i < out.size; i++) {
            printf("%02x ", out.buffer[i]);
            if ((i + 1) % 16 == 0) {
                putchar('\n');
            }
        }
        printf("\n");
    }
    
    if (verbose) {
        IPRINTF("NV_Read as string: ");
        for (uint16_t i = 0; i < out.size; i++) {
            unsigned char c = out.buffer[i];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        putchar('\n');
    }
}

// Decide whether we should retry on this RC
static int tpm_should_retry(uint32_t rc16)
{
    // Known transient RCs:
    // - 0x01DA: TPM_RC_TESTING (implementation is in self-test)
    // - 0x0092: TPM_RC_RETRY
    // - 0x0098: TPM_RC_YIELDED
    // Add more if needed.
    if (rc16 == 0x01DAu) {
        return 1;
    }
    if (rc16 == 0x0092u) {
        return 1;
    }
    if (rc16 == 0x0098u) {
        return 1;
    }
    return 0;
}

// Entry point for NV_Write fuzz target.
// - Reads mutation text file into nvwrite_fuzz_input_t
// - Defines NV space sized for fuzz
// - Builds a correct NV_Write, then applies mutations (flags0/flags1)
// - Sends the command and prints basic result
int nv_write_start_fuzz_test(struct options_t *fuzz_opt)
{
    nvwrite_fuzz_input_t input = { 0 };
    int rc = 0;
    int16_t write_offset_used = 0;
    uint32_t nv_index = 0;

    if (nvwrite_load_fuzz_text_file(fuzz_opt->infile, &input) != 0) {
        EPRINTF("Failed to parse input text: %s\n", fuzz_opt->infile);
        return -1;
    }

    // Safety guard: payload is required
    if (input.payload == NULL) {
        EPRINTF("Input payload is NULL\n");
        return -1;
    }
    if (input.payload_actual_len == 0) {
        // Fallback: use declared length if actual length was not set
        input.payload_actual_len = input.payload_len;
    }

    // Small settle delay helps some fTPM builds right after boot
    usleep(500 * 1000); // 500ms

    // 1) Define NV index with enough room:
    //    Choose max(declared, actual), clamp to [64..2048].
    uint16_t nv_data_size = input.payload_actual_len;
    if (input.payload_len > nv_data_size) {
        nv_data_size = input.payload_len;
    }
    if (nv_data_size < 64) {
        nv_data_size = 64;
    }
    if (nv_data_size > 2048) {
        nv_data_size = 2048;
    }

    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_SYS_CONTEXT *sys_ctx = init_sys_context(&tcti);
    if (!sys_ctx) {
        EPRINTF("Failed to init sys context\n");
        return -1;
    }

    if (find_free_nv_index(sys_ctx, &nv_index) < 0) {
        EPRINTF("Failed to find NV INDEX\n");
        rc = -1;
        goto free_sys_ctx;
    }

    // NV_DefineSpace
    {
        uint8_t cmd[512];
        uint8_t rsp[256];
        size_t cmd_len = 0;
        size_t rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_definespace(nv_index, nv_data_size, cmd, sizeof(cmd), &cmd_len) != 0) {
            EPRINTF("Failed to build NV_DefineSpace\n");
            rc = -1;
            goto free_sys_ctx;
        }

        if (send_tpm_cmd_mu(fuzz_opt->fd, cmd, cmd_len, rsp, &rsp_len, &last_rc) != 0) {
            EPRINTF("NV_DefineSpace failed (rc=0x%08x)\n", last_rc);
            rc = -1;
            goto free_sys_ctx;
        }

        DPRINTF("NV_DefineSpace OK (dataSize=%u)\n", nv_data_size);
    }

    // 2) NV_Write (build correct frame using ACTUAL bytes, then mutate)
    {
        uint8_t cmd[4096];
        uint8_t rsp[1024];
        size_t cmd_len = 0;

        nvwrite_layout_t layout = { 0 };

        // Build a correct NV_Write with ACTUAL payload size to avoid MU over-read.
        if (build_cmd_nv_write(nv_index,
                               input.payload,
                               input.payload_actual_len,
                               cmd, sizeof(cmd), &cmd_len,
                               &layout) != 0) {
            EPRINTF("Failed to build NV_Write\n");
            rc = -1;
            goto cleanup_undefine;
        }

        // 2-1) TPM2B_MAX_NV_BUFFER.size
        if ((layout.nvbuf_size_off + 2) <= cmd_len) {
            if ((input.flags0 & NV_WRITE_FLAGS0_MUTATE_DECLARED_SIZE_DELTA) != 0u) {
                uint16_t cur = be16_read(cmd, layout.nvbuf_size_off);
                uint16_t neu = (uint16_t)(cur + input.declared_size_delta);
                be16_write(cmd, layout.nvbuf_size_off, neu);
            } else {
                be16_write(cmd, layout.nvbuf_size_off, input.payload_len);
            }
        }

        // 2-2) authorizationSize
        if ((input.flags0 & NV_WRITE_FLAGS0_MUTATE_AUTHSIZE_DELTA) != 0u) {
            if ((layout.auth_size_off + 4) <= cmd_len) {
                uint32_t cur = be32_read(cmd, layout.auth_size_off);
                uint32_t neu = (uint32_t)(cur + (int32_t)input.authsize_delta);
                be32_write(cmd, layout.auth_size_off, neu);
            }
        }

        // 2-3) NV offset
        if ((input.flags0 & NV_WRITE_FLAGS0_MUTATE_OFFSET_DELTA) != 0u) {
            if ((layout.nv_offset_off + 2) <= cmd_len) {
                uint16_t cur = be16_read(cmd, layout.nv_offset_off);
                uint16_t neu = (uint16_t)(cur + input.offset_delta);
                be16_write(cmd, layout.nv_offset_off, neu);
            }
        }

        // 2-4) Swap handles (authHandle <-> nvIndex)
        if (((input.flags0 & NV_WRITE_FLAGS0_SWAP_HANDLES) != 0u) || (input.swap_handles != 0u)) {
            if ((layout.handles_off + 8) <= cmd_len) {
                uint8_t tmp[4];
                memcpy(tmp,                      &cmd[layout.handles_off],      4);
                memcpy(&cmd[layout.handles_off], &cmd[layout.handles_off + 4], 4);
                memcpy(&cmd[layout.handles_off + 4], tmp,                      4);
            }
        }

        // Send mutated command with retry on transient RCs
        {
            int attempts = 10;
            int delay_ms = 100;
            int ok = 0;
            write_offset_used = be16_read(cmd, layout.nv_offset_off);
            
            for (int i = 0; i < attempts; i++) {
                size_t rsp_len_try = sizeof(rsp);
                TPM2_RC rc_try = 0;

                if (send_tpm_cmd_mu(fuzz_opt->fd, cmd, cmd_len, rsp, &rsp_len_try, &rc_try) == 0) {
                    ok = 1;
                    break;
                }

                if (!tpm_should_retry(rc_base(rc_try))) {
                    EPRINTF("NV_Write failed (rc=0x%08x)\n", rc_try);
                    break;
                }

                usleep((useconds_t)delay_ms * 1000);
                if (delay_ms < 1000) {
                    delay_ms <<= 1;
                }
            }

            if (!ok) {
                rc = -1;
                goto cleanup_undefine;
            }
        }

        IPRINTF("NV_Write OK (declared=%u, actual=%u)\n",
               (unsigned)input.payload_len,
               (unsigned)input.payload_actual_len);
    }

    // 3) NV_Read back to verify the content we wrote
    {
        uint8_t cmd[512];
        uint8_t rsp[256];
        size_t cmd_len = 0;
        size_t rsp_len = sizeof(rsp);

        // Determine offset to read from:
        // Prefer the actual offset used in NV_Write if you kept it (write_offset_used).
        // Otherwise, fall back to 0.
        uint16_t offset_used = 0;
    #ifdef HAVE_WRITE_OFFSET_USED
        offset_used = write_offset_used;  // define this macro if you saved the offset after NV_Write
    #endif

        // Decide how many bytes to read safely:
        // - start from the intended payload size (actual)
        // - clamp by NV dataSize and offset
        uint16_t want = input.payload_actual_len;
        if (want == 0) {
            want = 6;  // fallback for simple cases
        }
        if (offset_used >= nv_data_size) {
            want = 0;  // nothing readable at/after this offset
        } else {
            uint16_t max_read = (uint16_t)(nv_data_size - offset_used);
            if (want > max_read) {
                want = max_read;
            }
        }

        if (want == 0) {
            EPRINTF("NV_Read skipped (offset=%u exceeds NV dataSize=%u)\n",
                (unsigned)offset_used, (unsigned)nv_data_size);
            goto after_read;
        }

        // Build NV_Read (with offset). If your builder does not accept an offset,
        // replace this call with your version and keep offset at 0, or add an offset parameter.
        if (build_cmd_nv_read(nv_index, want, write_offset_used, cmd, sizeof(cmd), &cmd_len) != 0) {
            EPRINTF("Failed to build NV_Read\n");
            rc = -1;
            goto cleanup_undefine;
        }

        // Send with retry for transient RCs (TESTING/RETRY/YIELDED)
        {
            int attempts = 10;
            int delay_ms = 100;
            int ok = 0;

            for (int i = 0; i < attempts; i++) {
                size_t rsp_len_try = sizeof(rsp);
                TPM2_RC rc_try = 0;

                if (send_tpm_cmd_mu(fuzz_opt->fd, cmd, cmd_len, rsp, &rsp_len_try, &rc_try) == 0) {
                    rsp_len = rsp_len_try;
                    ok = 1;
                    break;
                }

                if (!tpm_should_retry(rc_base(rc_try))) {
                    EPRINTF("NV_Read failed (rc=0x%08x)\n", rc_try);
                    rc = -1;
                    goto cleanup_undefine;
                }

                usleep((useconds_t)delay_ms * 1000);
                if (delay_ms < 1000) {
                    delay_ms <<= 1;
                }
            }

            if (!ok) {
                rc = -1;
                goto cleanup_undefine;
            }
        }

        DPRINTF("NV_Read OK (offset=%u, size=%u, rsp_len=0x%zx)\n",
            (unsigned)offset_used, (unsigned)want, rsp_len);

        dump_nv_read_response(rsp, rsp_len);

    after_read:
        ; // no-op
    }


cleanup_undefine:
    // Always attempt to undefine the NV space so the next run starts cleanly.
    {
        uint8_t cmd[512];
        uint8_t rsp[256];
        size_t cmd_len = 0;
        size_t rsp_len = sizeof(rsp);
        TPM2_RC last_rc = 0;

        if (build_cmd_nv_undefinespace(nv_index, cmd, sizeof(cmd), &cmd_len) == 0) {
            if (send_tpm_cmd_mu(fuzz_opt->fd, cmd, cmd_len, rsp, &rsp_len, &last_rc) == 0) {
                IPRINTF("NV_UndefineSpace OK\n");
            } else {
                EPRINTF("NV_UndefineSpace failed (rc=0x%08x)\n", last_rc);
            }
        } else {
            EPRINTF("Failed to build NV_UndefineSpace\n");
        }
    }

free_sys_ctx:
    if (sys_ctx) {
        Tss2_Sys_Finalize(sys_ctx);
        free(sys_ctx);
    }

    if (tcti) {
        Tss2_TctiLdr_Finalize(&tcti);
    }
    return rc;
}
