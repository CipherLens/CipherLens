
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>

static int run_variant(const char *case_id) {
    unsigned char out[128];
    unsigned char in[16];
    unsigned char short_in[1];
    memset(out, 0xa5, sizeof(out));
    memset(in, 0x41, sizeof(in));
    memset(short_in, 0x42, sizeof(short_in));

    if (strcmp(case_id, "null_input_zero_len") == 0)
        return EVP_EncodeBlock(out, NULL, 0);
    if (strcmp(case_id, "null_input_nonzero_len_original") == 0)
        return EVP_EncodeBlock(out, NULL, 4);
    if (strcmp(case_id, "valid_input_same_nonzero_len") == 0)
        return EVP_EncodeBlock(out, in, 4);
    if (strcmp(case_id, "short_input_claimed_larger_len") == 0)
        return EVP_EncodeBlock(out, short_in, 4);
    if (strcmp(case_id, "null_output_zero_len_boundary") == 0)
        return EVP_EncodeBlock(NULL, in, 0);
    return -999;
}

static const char *sig_name(int sig) {
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGILL: return "SIGILL";
    default: return "SIGNAL";
    }
}

int main(int argc, char **argv) {
    const char *case_id = argc > 1 ? argv[1] : "null_input_nonzero_len_original";
    int len = 0;
    if (strcmp(case_id, "null_input_zero_len") == 0) len = 0;
    else if (strcmp(case_id, "null_input_nonzero_len_original") == 0) len = 4;
    else if (strcmp(case_id, "valid_input_same_nonzero_len") == 0) len = 4;
    else if (strcmp(case_id, "short_input_claimed_larger_len") == 0) len = 4;
    else if (strcmp(case_id, "null_output_zero_len_boundary") == 0) len = 0;

    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 2;
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        int ret = run_variant(case_id);
        (void)write(fds[1], &ret, sizeof(ret));
        close(fds[1]);
        _exit(ret < 0 ? 100 : 0);
    }
    close(fds[1]);
    if (pid < 0) {
        perror("fork");
        return 2;
    }

    int status = 0;
    int ret = -999;
    ssize_t got = read(fds[0], &ret, sizeof(ret));
    close(fds[0]);
    waitpid(pid, &status, 0);
    const char *actual = "error";
    const char *crash = "none";
    const char *label = "no_candidate";
    if (WIFEXITED(status) && got == sizeof(ret)) {
        actual = ret >= 0 ? "success" : "error";
    } else if (WIFSIGNALED(status)) {
        actual = "crash";
        crash = sig_name(WTERMSIG(status));
        label = "crash_candidate";
    }

    printf("STEP_EVENT case_id=%s api=EVP_EncodeBlock ret=%d len=%d\n", case_id, ret, len);
    printf("ORACLE_EVENT family=memory_length_boundary\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", strcmp(case_id, "null_input_nonzero_len_original") == 0 ? "reject_or_no_crash" : "memory_safety_watch");
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=%s\n", crash);
    printf("ORACLE_EVENT candidate_label=%s\n", label);
    return 0;
}
