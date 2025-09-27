#pragma once
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>  // htons, htonl, ntohs, ntohl

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#define DEV_TPMRM0 "/dev/tpmrm0"

#define IPRINTF(fmt, ...) \
    do { \
        fprintf(stderr, "[+] %s:%d: " fmt, \
                __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#define EPRINTF(fmt, ...) \
    do { \
        fprintf(stderr, "[*] %s:%d: " fmt, \
                __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

extern int verbose;
#define DPRINTF(fmt, ...) \
    do { \
        if (verbose) { \
            fprintf(stderr, "[+] %s:%d: " fmt, \
                    __func__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

// Normalize a TPM RC to its 16-bit base (strip format/layer bits)
static inline uint32_t rc_base(uint32_t rc) 
{ 
    return rc & 0xFFFFu; 
}

// Write UINT16 in big-endian
static inline void be16_write(uint8_t *buf, size_t off, uint16_t v)
{
    uint16_t be = htons(v);
    memcpy(buf + off, &be, sizeof(be));
}

// Write UINT32 in big-endian
static inline void be32_write(uint8_t *buf, size_t off, uint32_t v)
{
    uint32_t be = htonl(v);
    memcpy(buf + off, &be, sizeof(be));
}

// Read UINT16 from big-endian
static inline uint16_t be16_read(const uint8_t *buf, size_t off)
{
    uint16_t be;
    memcpy(&be, buf + off, sizeof(be));
    return ntohs(be);
}

// Read UINT32 from big-endian
static inline uint32_t be32_read(const uint8_t *buf, size_t off)
{
    uint32_t be;
    memcpy(&be, buf + off, sizeof(be));
    return ntohl(be);
}

int open_tpm_dev(void);
void close_tpm_dev(int fd);

int send_tpm_cmd_mu(int fd, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, TPM2_RC *tpm_rc_out);
int marshal_pwap_auth(uint8_t *buf, size_t buf_sz, size_t *autharea_len);
int begin_cmd_sessions(UINT32 cc, uint8_t *buf, size_t buf_sz, size_t *off_io, size_t *size_off_out);
int finalize_cmd_size(uint8_t *buf, size_t buf_sz, size_t size_off, size_t total_off);