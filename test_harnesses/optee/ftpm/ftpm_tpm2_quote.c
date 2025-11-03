/*
  Single-line CSV -> parse -> build request into caller-provided buffer -> send_command()
  - Test kinds:
      * "qualifyingData,<size>,<byte-list>"
      * "invalid_sessions"
  - PCR is fixed: SHA256:PCR16.
  - Session: PWAP (empty password) for valid path; malformed variant for invalid_sessions.

  Comments in English; runtime messages in Japanese-friendly format.
*/
#include "common.h"
#include "fuzz_params.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_mu.h>

#define DEFAULT_AK_HANDLE 0x81010002u
#define REQ_MAX 8192
#define RSP_MAX 8192
#define QD_BUF_MAX 1024

/* -------------------- data model -------------------- */
typedef enum {
    TEST_QD_ONLY = 0,
    TEST_INVALID_SESSIONS
} TestKind;

typedef struct {
    TestKind kind;
    union {
        struct {            /* payload for TEST_QD_ONLY */
            uint16_t size;  /* qd.size (verbatim) */
            uint8_t  buf[QD_BUF_MAX];
            size_t   buf_len;
        } qd;
        struct {            /* payload for TEST_INVALID_SESSIONS */
            uint16_t tag;   /* e.g. TPM2_ST_NO_SESSIONS(0x8001) or TPM2_ST_SESSIONS(0x8002) */
            uint8_t  auth_raw[256];  /* arbitrary auth/session bytes to inject */
            size_t   auth_len;       /* length of auth_raw[] */
        } invsess;
    } u;
} ParsedInput;

/* -------------------- small helpers -------------------- */
static void trim(char *s)
{
    char *p = s;

    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }

    size_t n = strlen(s);

    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                 s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }
}

static unsigned long parse_number(const char *s)
{
    char *e = NULL;

    return s ? strtoul(s, &e, 0) : 0;
}

static size_t parse_byte_list(const char *s, uint8_t *out, size_t cap)
{
    if (!s) {
        return 0;
    }

    char *dup = strdup(s);

    if (!dup) {
        return 0;
    }

    trim(dup);

    size_t cnt = 0;
    for (char *t = strtok(dup, " "); t && cnt < cap; t = strtok(NULL, " ")) {
        trim(t);
        if (!*t) {
            continue;
        }
        unsigned long v = strtoul(t, NULL, 0);
        out[cnt++] = (uint8_t) (v & 0xFF);
    }

    free(dup);
    return cnt;
}

/* parse one-line CSV: fills ParsedInput */
static int parse_input_file_one_line(const char *path, ParsedInput *out,
                                     char *err, size_t errsz)
{
    FILE *f = fopen(path, "r");

    if (!f) {
        snprintf(err, errsz, "open failed: %s", strerror(errno));
        return -1;
    }

    char line[4096];

    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        snprintf(err, errsz, "empty file");
        return -1;
    }

    fclose(f);
    trim(line);

    if (!*line) {
        snprintf(err, errsz, "blank line");
        return -1;
    }

    /* split into up to 3 columns: c1,c2,c3 */
    char *c1 = line;
    char *c2 = NULL;
    char *c3 = NULL;
    char *p = line;
    char *comma = strchr(p, ',');

    if (comma) {
        *comma = '\0';
        p = comma + 1;
        c2 = p;
        comma = strchr(p, ',');
        if (comma) {
            *comma = '\0';
            p = comma + 1;
            c3 = p;
        }
    }

    trim(c1);
    if (c2) {
        trim(c2);
    }
    if (c3) {
        trim(c3);
    }

    /* case 1: qualifyingData,<size>,<byte-list> */
    if (strcmp(c1, "qualifyingData") == 0) {
        if (!c2 || !c3) {
            snprintf(err, errsz,
                     "qualifyingData requires 3 columns");
            return -1;
        }

        memset(out, 0, sizeof(*out));
        out->kind = TEST_QD_ONLY;

        unsigned long sz = parse_number(c2);

        if (sz > 0xFFFF) {
            sz = 0xFFFF;
        }

        out->u.qd.size = (uint16_t) sz;
        out->u.qd.buf_len =
            parse_byte_list(c3, out->u.qd.buf, QD_BUF_MAX);

        return 0;
    }

    /* case 2: invalid_sessions[,<tag>][,<auth-bytes>] */
    if (strcmp(c1, "invalid_sessions") == 0) {
        memset(out, 0, sizeof(*out));
        out->kind = TEST_INVALID_SESSIONS;

        /* default tag = TPM2_ST_NO_SESSIONS (0x8001) */
        out->u.invsess.tag = 0x8001;
        out->u.invsess.auth_len = 0;

        /* if 2nd column exists, treat it as tag */
        if (c2 && *c2) {
            unsigned long tag = parse_number(c2);

            /* keep it in 16 bits */
            out->u.invsess.tag = (uint16_t) tag;
        }

        /* if 3rd column exists, treat it as raw auth/session bytes */
        if (c3 && *c3) {
            out->u.invsess.auth_len =
                parse_byte_list(c3,
                                out->u.invsess.auth_raw,
                                sizeof(out->u.invsess.auth_raw));
        }

        return 0;
    }

    snprintf(err, errsz, "unknown test kind: %s", c1);
    return -1;
}

/* -------------------- common I/O -------------------- */
static ssize_t write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t left = len;

    while (left) {
        ssize_t w = write(fd, p, left);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        left -= (size_t) w;
        p += w;
    }
    return (ssize_t) len;
}

static ssize_t read_some(int fd, void *buf, size_t cap)
{
    ssize_t r = read(fd, buf, cap);

    if (r < 0 && errno == EINTR) {
        return read_some(fd, buf, cap);
    }
    return r;
}

static uint32_t parse_rsp_rc(const uint8_t *rsp, ssize_t rlen)
{
    if (rlen < 10) {
        return 0xffffffffu;
    }

    uint32_t be;

    memcpy(&be, rsp + 6, 4);
    return be32toh(be);
}

/* -------------------- shared marshal bits -------------------- */
static void marshal_pcr_sel_sha256_16(uint8_t **pp, uint8_t *base, size_t cap)
{
    TPML_PCR_SELECTION list;
    size_t off = 0;

    memset(&list, 0, sizeof(list));
    list.count = 1;
    list.pcrSelections[0].hash = TPM2_ALG_SHA256;
    list.pcrSelections[0].sizeofSelect = 3;
    memset(list.pcrSelections[0].pcrSelect, 0, 3);
    list.pcrSelections[0].pcrSelect[2] = 0x01; /* PCR16 -> byte2 bit0 */

    Tss2_MU_TPML_PCR_SELECTION_Marshal(
        &list, *pp, (size_t) (base + cap - *pp), &off
    );
    *pp += off;
}

/* -------------------- builders (build-only; no send) -------------------- */

/* Build a valid TPM2_Quote with PWAP(empty) and provided qd fields into req[].
   Returns request length, or 0 on error. */
static size_t build_qd_only(uint8_t *req, size_t req_cap,
                            uint32_t ak_handle,
                            uint16_t qd_size, const uint8_t *qd_buf,
                            size_t qd_buf_len)
{
    uint8_t *p = req;
    if (req_cap < 32) {
        return 0;
    }

    /* header: SESSIONS */
    *(uint16_t *) p = htobe16(TPM2_ST_SESSIONS);
    p += 2;
    uint32_t *size_ptr = (uint32_t *) p;
    p += 4;
    *(uint32_t *) p = htobe32(TPM2_CC_Quote);
    p += 4;

    /* handle: signingKey */
    *(uint32_t *) p = htobe32(ak_handle);
    p += 4;

    /* authSize + TPMS_AUTH_COMMAND (PWAP empty) */
    uint8_t *auth_size_pos = p;
    p += 4;
    TPMS_AUTH_COMMAND auth;
    memset(&auth, 0, sizeof(auth));
    auth.sessionHandle = TPM2_RS_PW;
    auth.nonce.size = 0;
    auth.sessionAttributes = 0;
    auth.hmac.size = 0;
    size_t off = 0;
    if (Tss2_MU_TPMS_AUTH_COMMAND_Marshal(
            &auth, p, (size_t) (req + req_cap - p), &off) != TSS2_RC_SUCCESS) {
        return 0;
    }
    p += off;
    *(uint32_t *) auth_size_pos = htobe32((uint32_t) off);

    /* qualifyingData */
    TPM2B_DATA qd;
    memset(&qd, 0, sizeof(qd));
    qd.size = (qd_size > sizeof(qd.buffer)) ?
              (UINT16) sizeof(qd.buffer) : qd_size;
    size_t copy = (qd_buf_len > sizeof(qd.buffer)) ?
                  sizeof(qd.buffer) : qd_buf_len;
    if (copy) {
        memcpy(qd.buffer, qd_buf, copy);
    }
    off = 0;
    if (Tss2_MU_TPM2B_DATA_Marshal(
            &qd, p, (size_t) (req + req_cap - p), &off) != TSS2_RC_SUCCESS) {
        return 0;
    }
    p += off;

    /* inScheme = ALG_NULL */
    TPMT_SIG_SCHEME scheme;
    memset(&scheme, 0, sizeof(scheme));
    scheme.scheme = TPM2_ALG_NULL;
    off = 0;
    if (Tss2_MU_TPMT_SIG_SCHEME_Marshal(
            &scheme, p, (size_t) (req + req_cap - p), &off) != TSS2_RC_SUCCESS) {
        return 0;
    }
    p += off;

    /* PCR selection fixed */
    marshal_pcr_sel_sha256_16(&p, req, req_cap);

    *(uint32_t *) size_ptr = htobe32((uint32_t) (p - req));
    return (size_t) (p - req);
}

/* Build an INVALID sessions packet to test tag/auth inconsistency.
 * Variant: tag is provided by caller, and optional raw auth/session bytes
 * can be injected. If auth_len == 0, a default PWAP is inserted to create
 * an inconsistency (same as older behavior).
 */
static size_t build_invalid_sessions(uint8_t *req, size_t req_cap,
                                     uint32_t ak_handle,
                                     uint16_t tag,
                                     const uint8_t *auth_raw,
                                     size_t auth_len)
{
    uint8_t *p = req;
    uint32_t *size_ptr;
    uint8_t *auth_size_pos;
    size_t off = 0;
    TPMS_AUTH_COMMAND auth;
    TPM2B_DATA qd;
    TPMT_SIG_SCHEME scheme;

    if (req_cap < 32) {
        return 0;
    }

    /* header: tag is supplied from parsed input */
    *(uint16_t *) p = htobe16(tag);
    p += 2;

    size_ptr = (uint32_t *) p;
    p += 4;

    *(uint32_t *) p = htobe32(TPM2_CC_Quote);
    p += 4;

    /* handle */
    *(uint32_t *) p = htobe32(ak_handle);
    p += 4;

    /* authSize field (we will fill it in below) */
    auth_size_pos = p;
    p += 4;

    if (auth_len > 0 && auth_raw != NULL) {
        /* use raw auth/session bytes from file, as-is */
        if (auth_len > (size_t) (req + req_cap - p)) {
            /* not enough space in req buffer */
            return 0;
        }

        memcpy(p, auth_raw, auth_len);
        p += auth_len;

        *(uint32_t *) auth_size_pos = htobe32((uint32_t) auth_len);
    } else {
        /* fallback: build a normal PWAP auth to create inconsistency */
        memset(&auth, 0, sizeof(auth));
        auth.sessionHandle = TPM2_RS_PW;
        auth.hmac.size = 0;

        off = 0;
        if (Tss2_MU_TPMS_AUTH_COMMAND_Marshal(
                &auth, p, (size_t) (req + req_cap - p), &off)
            != TSS2_RC_SUCCESS) {
            return 0;
        }

        p += off;
        *(uint32_t *) auth_size_pos = htobe32((uint32_t) off);
    }

    /* minimal parameters (same as before) */
    memset(&qd, 0, sizeof(qd));
    qd.size = 0;

    off = 0;
    if (Tss2_MU_TPM2B_DATA_Marshal(
            &qd, p, (size_t) (req + req_cap - p), &off)
        != TSS2_RC_SUCCESS) {
        return 0;
    }
    p += off;

    memset(&scheme, 0, sizeof(scheme));
    scheme.scheme = TPM2_ALG_NULL;

    off = 0;
    if (Tss2_MU_TPMT_SIG_SCHEME_Marshal(
            &scheme, p, (size_t) (req + req_cap - p), &off)
        != TSS2_RC_SUCCESS) {
        return 0;
    }
    p += off;

    /* PCR selection fixed */
    marshal_pcr_sel_sha256_16(&p, req, req_cap);

    *(uint32_t *) size_ptr = htobe32((uint32_t) (p - req));

    return (size_t) (p - req);
}


/* -------------------- common sender -------------------- */
/* Open TPM_DEV, write req/reqlen, read response, print rc & hexdump.
   Returns 0 on I/O success (not TPM success); caller inspects rc if needed. */
static int send_command(int fd, const uint8_t *req, size_t reqlen)
{
    uint8_t rsp[RSP_MAX] = { 0x0 };

    if (write_all(fd, req, reqlen) < 0) {
        EPRINTF("write error\n");
        return -1;
    }

    ssize_t rlen = read_some(fd, rsp, sizeof(rsp));
    if (rlen < 0) {
        IPRINTF("read error\n");
        return -1;
    }

    uint32_t rc = parse_rsp_rc(rsp, rlen);
    IPRINTF("responce length=%zd  rc=0x%08x\n", rlen, rc);

    size_t dump = (rlen > 64) ? 64 : (size_t) rlen;
    IPRINTF("Read %zu bytes:", dump);

    for (size_t i = 0; i < dump; i++) {
        if (i % 16 == 0) {
            printf("\n%04zx: ", i);
        }
        printf("%02x ", rsp[i]);
    }
    printf("\n");

    return 0;
}

/* -------------------- main: parse -> build -> send -------------------- */
int ftpm_tpm2_quote_start_fuzz_test(options_t *fuzz_opt)
{
    const char *infile = fuzz_opt->infile;
    uint32_t ak = DEFAULT_AK_HANDLE;

    ParsedInput pi;
    char err[256];

    if (parse_input_file_one_line(infile, &pi, err, sizeof(err)) != 0) {
        fprintf(stderr, "parse error: %s\n", err);
        return 3;
    }

    uint8_t req[REQ_MAX];
    size_t reqlen = 0;

    switch (pi.kind) {
    case TEST_QD_ONLY:
        reqlen = build_qd_only(req, sizeof(req), ak,
                               pi.u.qd.size,
                               pi.u.qd.buf,
                               pi.u.qd.buf_len);
        if (!reqlen) {
            fprintf(stderr, "build_qd_only failed\n");
            return 4;
        }
        printf("[qd]Send qd.size=0x%04x  buffer_len=%zu\n",
               pi.u.qd.size, pi.u.qd.buf_len);
        break;

    case TEST_INVALID_SESSIONS:
        reqlen = build_invalid_sessions(req, sizeof(req), ak,
                                        pi.u.invsess.tag,
                                        pi.u.invsess.auth_raw,
                                        pi.u.invsess.auth_len);
        if (!reqlen) {
            fprintf(stderr, "build_invalid_sessions failed\n");
            return 5;
        }
        printf("[invalid_sessions]Send packet (tag=0x%04x, auth_len=%zu)\n",
               pi.u.invsess.tag, pi.u.invsess.auth_len);
        break;

    default:
        fprintf(stderr, "unknown kind\n");
        return 6;
    }

    return send_command(fuzz_opt->fd, req, reqlen);
}

