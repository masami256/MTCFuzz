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

#include "common.h"

#include "ftpm_ta.h"
#include "ftpm_nv.h"

int main(void)
{
    int rc = 0;

    printf("[+]Test start\n");
    if (check_ftpm_ta())
        return -1;
    printf("[+]TA check ok\n");

    int fd = open_tpm_dev();
    if (fd < 0) {
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
            rc = -1;
            goto cleanup;
        }

        if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_DefineSpace failed (rc=0x%08x)\n", last_rc);
            rc = -1;
            goto cleanup;
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
                if (delay_ms < 1000) {
                    delay_ms <<= 1;
                }
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
            rc = -1;
        } else if (send_tpm_cmd_mu(fd, cmd, cmd_len, rsp, &rsp_len, &last_rc)) {
            printf("[*]NV_UndefineSpace failed (rc=0x%08x)\n", last_rc);
            rc = -1;
        } else {
            printf("[+]NV_UndefineSpace OK\n");
        }
    }
    
    printf("[+]Done\n");

cleanup:
    close_tpm_dev(fd);
    return rc;
}
