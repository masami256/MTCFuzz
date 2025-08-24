#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include "sbi_fuzz.h"

#define SBI_FUZZ_DEVICE "/dev/sbi_fuzz"

static struct option long_options[] = {
    { "output-dir", required_argument, NULL, 'o'},
    { "eid", required_argument, NULL, 'e'},
    { "fid", required_argument, NULL, 'f'},
    { "a0", required_argument, NULL, 'A'},
    { "a1", required_argument, NULL, 'B'},
    { "a2", required_argument, NULL, 'C'},
    { "a3", required_argument, NULL, 'D'},
    { "a4", required_argument, NULL, 'E'},
    { "a5", required_argument, NULL, 'F'},
    { "notrace", no_argument, NULL, 'n'},
    { "help", no_argument, NULL, 'h' },
    {0, 0, NULL, 0}
};

int write_result(struct sbi_data *params, const char *output_dir)
{
    FILE *fp;
    char filename[256];

    snprintf(filename, sizeof(filename), "%s/ecall_result.json", output_dir);
    fp = fopen(filename, "w");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"eid\": \"0x%lx\",\n", params->eid);
    fprintf(fp, "  \"fid\": \"0x%lx\",\n", params->fid);
    fprintf(fp, "  \"a0\": \"0x%lx\",\n", params->a0);
    fprintf(fp, "  \"a1\": \"0x%lx\",\n", params->a1);
    fprintf(fp, "  \"a2\": \"0x%lx\",\n", params->a2);
    fprintf(fp, "  \"a3\": \"0x%lx\",\n", params->a3);
    fprintf(fp, "  \"a4\": \"0x%lx\",\n", params->a4);
    fprintf(fp, "  \"a5\": \"0x%lx\",\n", params->a5);
    fprintf(fp, "  \"error\": \"0x%lx\",\n", params->ret.error);
    fprintf(fp, "  \"value\": \"0x%lx\"\n", params->ret.value);
    fprintf(fp, "}\n");
    fclose(fp);

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    int fd;
    int opt;
    int opt_index = 0;
    struct sbi_data params = { 0x0 };

    char output_dir[256] = {0};

    while ((opt = getopt_long_only(argc, argv, "", long_options, &opt_index)) != -1) {
        switch (opt) {
            case 'o':
                strncpy(output_dir, optarg, sizeof(output_dir) - 1);
                break;
            case 'h':
                fprintf(stderr, "Usage: %s [options]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  --output-dir <prefix>  output directory\n");
                fprintf(stderr, "  --eid <eid>         Specify EID\n");
                fprintf(stderr, "  --fid <fid>         Specify FID\n");
                fprintf(stderr, "  --a0 <value>         Specify a0 value\n");
                fprintf(stderr, "  --a1 <value>         Specify a1 value\n");
                fprintf(stderr, "  --a3 <value>         Specify a3 value\n");
                fprintf(stderr, "  --a4 <value>         Specify a4 value\n");
                fprintf(stderr, "  --a5 <value>         Specify a5 value\n");
                fprintf(stderr, "  --notrace            do not trace kcov and sbi_cov\n");
                fprintf(stderr, "  --help               Show this help message\n");
                return 0;
            case 'e':
                params.eid = strtoul(optarg, NULL, 16);
                break;
            case 'f':
                params.fid = strtoul(optarg, NULL, 16);
                break;
            case 'A':
                params.a0 = strtoul(optarg, NULL, 16);
                break;
            case 'B':
                params.a1 = strtoul(optarg, NULL, 16);
                break;
            case 'C':
                params.a2 = strtoul(optarg, NULL, 16);
                break;
            case 'D':
                params.a3 = strtoul(optarg, NULL, 16);
                break;
            case 'E':
                params.a4 = strtoul(optarg, NULL, 16);
                break;
            case 'F':
                params.a5 = strtoul(optarg, NULL, 16);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                return -1;
        }
    }

    if (strlen(output_dir) == 0) {
        fprintf(stderr, "Output directory name is required\n");
        return -1;
    }
    
    fd = open(SBI_FUZZ_DEVICE, O_RDWR);
    if (fd < 0) {
        perror("[*]Failed to open device");
        return -1;
    }

    ioctl(fd, SBI_FUZZ_IOCTL_EXEC_ECALL, &params);

    ret = write_result(&params, output_dir);

    close(fd);

    return ret;
}