#pragma once

// command-line options and globals
typedef enum {
    TARGET_UNKNOWN = 0,
    TARGET_NVWRITE,
} target_t;

/* Forward declaration of struct options_t so that the function pointer can use it */
struct options_t;

/* Define function pointer type first */
typedef int (*start_fuzz_test)(struct options_t *fuzz_opt);

/* Now define the struct using the function pointer type */
typedef struct options_t {
    target_t target;       // required: --target=nvwrite
    int fd;                // TPM device fd
    start_fuzz_test func;  // pointer to test entry function
    const char *infile;    // optional: --in (mutation text file)
} options_t;
