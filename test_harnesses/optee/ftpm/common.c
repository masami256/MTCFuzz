#include "common.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/* Send a raw TPM command, unmarshal the 10-byte response header with MU,
 * read the remaining bytes, and optionally return the TPM RC.
 * Returns 0 if TPM_RC_SUCCESS, otherwise -1 (caller can inspect tpm_rc_out).
 */
int send_tpm_cmd_mu(int fd,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len,
                           TPM2_RC *tpm_rc_out)
{
    // Transmit command
    ssize_t w = write(fd, in, in_len);
    if (w != (ssize_t)in_len) {
        return -1;
    }

    // Read fixed-size response header (10 bytes)
    uint8_t hdr_buf[10];
    ssize_t r = read(fd, hdr_buf, sizeof(hdr_buf));
    if (r != (ssize_t)sizeof(hdr_buf)) {
        return -1;
    }

    // Unmarshal: tag (TPM2_ST), paramSize (UINT32), responseCode (UINT32)
    size_t off = 0;
    TPM2_ST tag = 0;
    UINT32 paramSize = 0;
    TPM2_RC rc = 0;

    if (Tss2_MU_TPM2_ST_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &tag)) return -1;
    if (Tss2_MU_UINT32_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &paramSize)) return -1;
    if (Tss2_MU_UINT32_Unmarshal(hdr_buf, sizeof(hdr_buf), &off, &rc)) return -1;

    if (tpm_rc_out) *tpm_rc_out = rc;

    if (paramSize < sizeof(hdr_buf) || paramSize > *out_len) {
        return -1;
    }

    memcpy(out, hdr_buf, sizeof(hdr_buf));
    size_t remaining = paramSize - sizeof(hdr_buf);
    if (remaining) {
        ssize_t r2 = read(fd, out + sizeof(hdr_buf), remaining);
        if (r2 != (ssize_t)remaining) {
            return -1;
        }
    }
    *out_len = paramSize;

    return (rc == TPM2_RC_SUCCESS) ? 0 : -1;
}

// Marshal one PWAP AuthArea (TPM_RS_PW, empty hmac) and return its byte size.
int marshal_pwap_auth(uint8_t *buf, size_t buf_sz, size_t *autharea_len)
{
    // TPMS_AUTH_COMMAND: sessionHandle, nonce(size=0), sessionAttributes(1B), hmac(size=0)
    TPMS_AUTH_COMMAND a;
    a.sessionHandle = TPM2_RS_PW;      // password session
    a.nonce.size = 0;                   // no nonce
    a.sessionAttributes = 0;            // no attributes
    a.hmac.size = 0;                    // empty password

    size_t off = 0;
    TSS2_RC rc = Tss2_MU_TPMS_AUTH_COMMAND_Marshal(&a, buf, buf_sz, &off);
    if (rc != TSS2_RC_SUCCESS) {
        return -1;
    }
    *autharea_len = off;
    return 0;
}

// Begin a "SESSIONS" command header: tag, size placeholder, commandCode.
int begin_cmd_sessions(UINT32 cc, uint8_t *buf, size_t buf_sz,
                              size_t *off_io, size_t *size_off_out)
{
    size_t off = *off_io;
    if (Tss2_MU_TPM2_ST_Marshal(TPM2_ST_SESSIONS, buf, buf_sz, &off)) {
        return -1;
    }
    UINT32 size_placeholder = 0;
    size_t size_off = off;
    if (Tss2_MU_UINT32_Marshal(size_placeholder, buf, buf_sz, &off)) {
        return -1;
    }
    if (Tss2_MU_UINT32_Marshal(cc, buf, buf_sz, &off)) {
        return -1;
    }
    *off_io = off;
    *size_off_out = size_off;
    return 0;
}

// Backfill the total command size at 'size_off'.
int finalize_cmd_size(uint8_t *buf, size_t buf_sz, size_t size_off, size_t total_off)
{
    UINT32 total = (UINT32)total_off;
    size_t tmp = size_off;
    return (Tss2_MU_UINT32_Marshal(total, buf, buf_sz, &tmp) == TSS2_RC_SUCCESS) ? 0 : -1;
}

int open_tpm_dev(void)
{
    int fd = open(DEV_TPMRM0, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("[*]Failed to open %s: %s\n", DEV_TPMRM0, strerror(errno));
        return -1;
    }
    return fd;
}

void close_tpm_dev(int fd)
{
    close(fd);
}