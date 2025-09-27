#pragma once
#include "common.h"
#include "fuzz_params.h"
#include <stdio.h>

// flags0 bit definitions for NV_Write mutations
#define NV_WRITE_FLAGS0_MUTATE_DECLARED_SIZE_DELTA   (1u << 0)  // Modify nvbuf.size by declared_size_delta
#define NV_WRITE_FLAGS0_MUTATE_AUTHSIZE_DELTA        (1u << 1)  // Modify authorizationSize by authsize_delta
#define NV_WRITE_FLAGS0_MUTATE_OFFSET_DELTA          (1u << 2)  // Modify NV offset by offset_delta
#define NV_WRITE_FLAGS0_SWAP_HANDLES                 (1u << 3)  // Swap authHandle <-> nvIndex

// Reserve higher bits for future NV_Write mutations
#define NV_WRITE_FLAGS0_RESERVED4                    (1u << 4)
#define NV_WRITE_FLAGS0_RESERVED5                    (1u << 5)
#define NV_WRITE_FLAGS0_RESERVED6                    (1u << 6)
#define NV_WRITE_FLAGS0_RESERVED7                    (1u << 7)

// flags1 bit definitions for NV_Write advanced mutations
#define NV_WRITE_FLAGS1_MUTATE_TAG_NO_SESSIONS       (1u << 0)  // Force header.tag = TPM2_ST_NO_SESSIONS
#define NV_WRITE_FLAGS1_MUTATE_REMOVE_AUTHAREA       (1u << 1)  // Remove AuthArea completely
#define NV_WRITE_FLAGS1_MUTATE_DUPLICATE_AUTHAREA    (1u << 2)  // Duplicate AuthArea (PWAP twice)
#define NV_WRITE_FLAGS1_MUTATE_RANDOMIZE_HANDLE      (1u << 3)  // Randomize handles (authHandle/nvIndex)

// Reserve bits 4–7
#define NV_WRITE_FLAGS1_RESERVED4                    (1u << 4)
#define NV_WRITE_FLAGS1_RESERVED5                    (1u << 5)
#define NV_WRITE_FLAGS1_RESERVED6                    (1u << 6)
#define NV_WRITE_FLAGS1_RESERVED7                    (1u << 7)

// Layout descriptor for a TPM2_NV_Write command built with MU.
// Records byte offsets of fields that may be mutated by the fuzzer.
typedef struct nvwrite_layout_s {
    uint32_t cc;            // commandCode (TPM2_CC_NV_Write)
    size_t   hdr_size_off;  // offset of header 'size' field (UINT32)
    size_t   total_len;     // final command length (after finalize_cmd_size)

    size_t   handles_off;   // start of handles array (authHandle, nvIndex)

    size_t   auth_size_off; // offset of authorizationSize (UINT32)
    size_t   auth_off;      // start offset of first AuthArea (PWAP)

    size_t   params_off;    // start of parameters after AuthArea

    size_t   nvbuf_size_off;// offset of TPM2B_MAX_NV_BUFFER.size (UINT16)
    size_t   nv_offset_off; // offset of NV offset parameter (UINT16)
} nvwrite_layout_t;

// Fuzzer input loaded from mutated.txt (8-line text format).
// payload_len: declared size from line7 (used to overwrite nvbuf.size)
// payload_actual_len: number of bytes parsed from line8 (safe data size)
typedef struct {
    uint8_t  flags0;
    uint8_t  flags1;
    int16_t  declared_size_delta;   // signed 16-bit
    int16_t  offset_delta;          // signed 16-bit
    int16_t  authsize_delta;        // signed 16-bit
    uint32_t swap_handles;          // 0 or 1
    uint16_t payload_len;           // declared size (do not overwrite)
    uint16_t payload_actual_len;    // parsed payload length from hex string
    uint8_t *payload;               // heap buffer of actual bytes
} nvwrite_fuzz_input_t;

int nv_write_start_fuzz_test(options_t *fuzz_opt);
int build_cmd_nv_definespace(uint32_t nv_index, uint16_t data_size, uint8_t *buf, size_t buf_sz, size_t *out_len);
int build_cmd_nv_write(uint32_t nv_index, const uint8_t *data, uint16_t data_len, uint8_t *buf, size_t buf_sz, size_t *out_len, nvwrite_layout_t *layout);
int build_cmd_nv_read(uint32_t nv_index, uint16_t read_size, uint8_t *buf, size_t buf_sz, size_t *out_len);
int build_cmd_nv_undefinespace(uint32_t nv_index, uint8_t *buf, size_t buf_sz, size_t *out_len);
void dump_nv_read_response(const uint8_t *rsp, size_t rsp_len);