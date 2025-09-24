#pragma once
#include <stdio.h>

int build_cmd_nv_definespace(uint32_t nv_index, uint16_t data_size, uint8_t *buf, size_t buf_sz, size_t *out_len);
int build_cmd_nv_write(uint32_t nv_index, const uint8_t *data, uint16_t data_len, uint8_t *buf, size_t buf_sz, size_t *out_len);
int build_cmd_nv_read(uint32_t nv_index, uint16_t read_size, uint8_t *buf, size_t buf_sz, size_t *out_len);
int build_cmd_nv_undefinespace(uint32_t nv_index, uint8_t *buf, size_t buf_sz, size_t *out_len);
void dump_nv_read_response(const uint8_t *rsp, size_t rsp_len);