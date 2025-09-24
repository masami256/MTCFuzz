#pragma once
#include <stdint.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#define DEV_TPMRM0 "/dev/tpmrm0"

#define IPRINTF(fmt, ...) \
    do { \
        fprintf(stderr, "[INFO] %s:%d: " fmt "\n", \
                __func__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define EPRINTF(fmt, ...) \
    do { \
        fprintf(stderr, "[ERROR] %s:%d: " fmt "\n", \
                __func__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define DPRINTF(fmt, ...) \
    do { \
        fprintf(stderr, "[DEBUG] %s:%d: " fmt "\n", \
                __func__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)
    
// Choose an NV index in the NV handle range (0x01000000 - 0x01FFFFFF)
#define NV_INDEX   0x0100F00Du

// Normalize a TPM RC to its 16-bit base (strip format/layer bits)
static inline uint32_t rc_base(uint32_t rc) 
{ 
    return rc & 0xFFFFu; 
}

int open_tpm_dev(void);
void close_tpm_dev(int fd);

int send_tpm_cmd_mu(int fd, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, TPM2_RC *tpm_rc_out);
int marshal_pwap_auth(uint8_t *buf, size_t buf_sz, size_t *autharea_len);
int begin_cmd_sessions(UINT32 cc, uint8_t *buf, size_t buf_sz, size_t *off_io, size_t *size_off_out);
int finalize_cmd_size(uint8_t *buf, size_t buf_sz, size_t size_off, size_t total_off);