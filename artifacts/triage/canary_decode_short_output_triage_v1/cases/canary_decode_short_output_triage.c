
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <openssl/evp.h>

#define PREFIX 16
#define SUFFIX 16
#define ARENA 96

struct variant {
    const char *case_id;
    const char *input;
    int input_len;
    int out_size;
    int disabled;
    int malformed;
    int contract_boundary;
    const char *expected;
};

static const struct variant variants[] = {
    {"decode_valid_exact_output_buffer", "QUJDREVGR0g=", 12, 9, 0, 0, 0, "success_or_no_crash"},
    {"decode_valid_one_byte_short_output_buffer", "QUJDREVGR0g=", 12, 8, 0, 0, 1, "contract_boundary_observation"},
    {"decode_valid_zero_output_buffer_disabled_or_guarded", "QUJDREVGR0g=", 12, 0, 1, 0, 1, "contract_boundary_observation"},
    {"decode_malformed_exact_output_buffer", "!!!!====", 8, 6, 0, 1, 0, "memory_safety_watch"},
    {"decode_malformed_short_output_buffer", "!!!!====", 8, 5, 0, 1, 1, "contract_boundary_observation"},
    {"decode_padding_edge_short_output_buffer", "QQ======", 8, 5, 0, 0, 1, "contract_boundary_observation"},
    {"original_input_len_mismatch", "QUJDREVGR0g=", 16, 16, 0, 0, 1, "contract_boundary_observation"},
};

static const struct variant *find_variant(const char *case_id) {
    size_t n = sizeof(variants) / sizeof(variants[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(variants[i].case_id, case_id) == 0)
            return &variants[i];
    }
    return NULL;
}

static int expected_max_output(int input_len) {
    return ((input_len + 3) / 4) * 3;
}

static int run_variant(const struct variant *v, int *prefix_ok, int *suffix_ok) {
    unsigned char arena[ARENA];
    unsigned char *payload = arena + PREFIX;
    memset(arena, 0xa5, sizeof(arena));
    if (v->disabled) {
        *prefix_ok = 1;
        *suffix_ok = 1;
        return -777;
    }
    int ret = EVP_DecodeBlock(payload, (const unsigned char *)v->input, v->input_len);
    *prefix_ok = 1;
    *suffix_ok = 1;
    for (int i = 0; i < PREFIX; i++) {
        if (arena[i] != 0xa5)
            *prefix_ok = 0;
    }
    for (int i = PREFIX + v->out_size; i < PREFIX + v->out_size + SUFFIX && i < ARENA; i++) {
        if (arena[i] != 0xa5)
            *suffix_ok = 0;
    }
    return ret;
}

static const char *sig_name(int sig) {
    switch (sig) {
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    default: return "SIGNAL";
    }
}

int main(int argc, char **argv) {
    const char *case_id = argc > 1 ? argv[1] : "decode_valid_exact_output_buffer";
    const struct variant *v = find_variant(case_id);
    if (v == NULL) {
        fprintf(stderr, "unknown case_id\n");
        return 2;
    }
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 2;
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        int prefix_ok = 1, suffix_ok = 1;
        int ret = run_variant(v, &prefix_ok, &suffix_ok);
        int data[3] = {ret, prefix_ok, suffix_ok};
        (void)write(fds[1], data, sizeof(data));
        close(fds[1]);
        _exit(0);
    }
    close(fds[1]);
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    int data[3] = {-999, 0, 0};
    ssize_t got = read(fds[0], data, sizeof(data));
    close(fds[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    int ret = got == sizeof(data) ? data[0] : -999;
    int prefix_ok = got == sizeof(data) ? data[1] : 0;
    int suffix_ok = got == sizeof(data) ? data[2] : 0;
    const char *actual = ret >= 0 ? "success" : "error";
    const char *crash = "none";
    const char *label = "no_candidate";
    if (WIFSIGNALED(status)) {
        actual = "crash";
        crash = sig_name(WTERMSIG(status));
        label = "sanitizer_candidate";
    } else if (!prefix_ok || !suffix_ok) {
        label = v->contract_boundary ? "contract_boundary_observation" : "memory_safety_candidate";
    } else if (v->contract_boundary && ret >= 0) {
        label = "contract_boundary_observation";
    }
    int canary_corrupted = (!prefix_ok || !suffix_ok);
    printf("STEP_EVENT case_id=%s api=EVP_DecodeBlock input_len=%d out_buf_size=%d ret=%d\n", v->case_id, v->input_len, v->out_size, ret);
    printf("STEP_EVENT case_id=%s expected_max_output=%d actual_ret=%d\n", v->case_id, expected_max_output(v->input_len), ret);
    printf("STEP_EVENT case_id=%s prefix_canary_ok=%d suffix_canary_ok=%d\n", v->case_id, prefix_ok, suffix_ok);
    printf("ORACLE_EVENT family=buffer_canary_boundary\n");
    printf("ORACLE_EVENT case_id=%s\n", v->case_id);
    printf("ORACLE_EVENT trigger_api=EVP_DecodeBlock\n");
    printf("ORACLE_EVENT expected_behavior=%s\n", v->expected);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=%s\n", crash);
    printf("ORACLE_EVENT canary_corrupted=%d\n", canary_corrupted);
    printf("ORACLE_EVENT contract_boundary=%d\n", v->contract_boundary);
    printf("ORACLE_EVENT candidate_label=%s\n", label);
    return 0;
}
